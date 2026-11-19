package main

import (
    "bufio"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/netip"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/conn"
    "github.com/amnezia-vpn/amneziawg-go/v3/device"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    box "github.com/sagernet/sing-box"
    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/adapter/certificate"
    "github.com/sagernet/sing-box/adapter/endpoint"
    "github.com/sagernet/sing-box/adapter/inbound"
    "github.com/sagernet/sing-box/adapter/outbound"
    boxservice "github.com/sagernet/sing-box/adapter/service"
    "github.com/sagernet/sing-box/dns"
    "github.com/sagernet/sing-box/dns/transport"
    "github.com/sagernet/sing-box/dns/transport/fakeip"
    "github.com/sagernet/sing-box/log"
    "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing-box/protocol/direct"
    "github.com/sagernet/sing-box/protocol/mixed"
    tunin "github.com/sagernet/sing-box/protocol/tun"
    sjson "github.com/sagernet/sing/common/json"
    M "github.com/sagernet/sing/common/metadata"
    "golang.org/x/net/dns/dnsmessage"
    "golang.org/x/sys/windows"
)

type awgOutbound struct {outbound.Adapter; stack *netstack.Net; address netip.Addr; count atomic.Int64; web atomic.Int64}
func (a *awgOutbound) DialContext(ctx context.Context,n string,d M.Socksaddr)(net.Conn,error){
    if a.stack==nil{return nil,errors.New("offline")}
    a.count.Add(1)
    if d.Port==443 || d.Port==80 {a.web.Add(1)}
    if n=="tcp"{n="tcp4"};if n=="udp"{n="udp4"}
    return a.stack.DialContext(ctx,n,d.String())
}
func (a *awgOutbound) ListenPacket(ctx context.Context,d M.Socksaddr)(net.PacketConn,error){
    if err:=ctx.Err();err!=nil{return nil,err}
    if a.stack==nil{return nil,errors.New("offline")};a.count.Add(1)
    if d.Addr.IsValid()&&!d.Addr.Unmap().Is4(){return nil,errors.New("ipv6 unsupported")}
    if !a.address.Is4(){return nil,errors.New("local ipv4 missing")}
    // Empty net.UDPAddr has no address family. AWG's netstack forwards
    // protocol number zero to gVisor, which panics. Bind IPv4 explicitly.
    packet,err:=a.stack.ListenUDPAddrPort(netip.AddrPortFrom(a.address,0))
    if err!=nil{return nil,err}
    return &udp4PacketConn{PacketConn:packet},nil
}
type udp4PacketConn struct{net.PacketConn}
func (c *udp4PacketConn) WriteTo(data []byte,destination net.Addr)(int,error){
    udp,ok:=destination.(*net.UDPAddr);if !ok{return 0,errors.New("udp address type")}
    ip:=udp.IP.To4();if ip==nil{return 0,errors.New("udp ipv4 required")}
    // net.IPv4 returns a 16-byte IPv4-mapped address. This gVisor stack
    // requires the four-byte representation on an IPv4 UDP endpoint.
    return c.PacketConn.WriteTo(data,&net.UDPAddr{IP:ip,Port:udp.Port})
}
func (a *awgOutbound) ListenPacketWithDestination(ctx context.Context,d M.Socksaddr)(net.PacketConn,netip.Addr,error){
    if a.stack==nil{return nil,netip.Addr{},errors.New("offline")}
    resolved:=d.Addr.Unmap()
    if d.Fqdn!=""{
        addresses,err:=a.stack.LookupContextHost(ctx,d.Fqdn);if err!=nil{return nil,netip.Addr{},err}
        for _,address:=range addresses{ip,e:=netip.ParseAddr(address);if e==nil&&ip.Unmap().Is4(){resolved=ip.Unmap();break}}
    }
    if !resolved.Is4(){return nil,netip.Addr{},errors.New("udp ipv4 destination required")}
    packet,err:=a.ListenPacket(ctx,M.SocksaddrFrom(resolved,d.Port))
    return packet,resolved,err
}
func registry(a *awgOutbound) context.Context {
    ir:=inbound.NewRegistry();tunin.RegisterInbound(ir);mixed.RegisterInbound(ir)
    or:=outbound.NewRegistry();direct.RegisterOutbound(or)
    outbound.Register[struct{}](or,"finland-awg",func(ctx context.Context,r adapter.Router,l log.ContextLogger,tag string,_ struct{})(adapter.Outbound,error){
        a.Adapter=outbound.NewAdapter("finland-awg",tag,[]string{"tcp","udp"},nil);return a,nil
    })
    dr:=dns.NewTransportRegistry();transport.RegisterTCP(dr);transport.RegisterUDP(dr);fakeip.RegisterTransport(dr)
    return box.Context(context.Background(),ir,or,endpoint.NewRegistry(),dr,boxservice.NewRegistry(),certificate.NewRegistry())
}
func options(in Input,a *awgOutbound,proxyOnly bool)(context.Context,option.Options,error){
    ctx:=registry(a);var o option.Options
    b,err:=routerConfig(in,proxyOnly);if err!=nil{return ctx,o,err}
    err=sjson.UnmarshalContext(ctx,b,&o);if o.Log!=nil{o.Log.DisableColor=true};return ctx,o,err
}

var output sync.Mutex
func event(name string,values obj){output.Lock();defer output.Unlock();if values==nil{values=obj{}};values["event"]=name;_ = json.NewEncoder(os.Stdout).Encode(values)}

func startAWG(in Input)(*device.Device,*netstack.Net,error){
    addr,err:=netip.ParseAddr(in.Address);if err!=nil||!addr.Is4(){return nil,nil,errors.New("address")}
    servers:=[]netip.Addr{}
    for _,s:=range in.DNS {ip,e:=netip.ParseAddr(s);if e!=nil||!ip.Is4(){return nil,nil,errors.New("dns")};servers=append(servers,ip)}
    t,stack,err:=netstack.CreateNetTUN([]netip.Addr{addr},servers,1280);if err!=nil{return nil,nil,err}
    b:=conn.NewDefaultBind()
    d:=device.NewDevice(t,b,device.NewLogger(device.LogLevelSilent,""))
    if err=d.IpcSet(in.UAPI);err!=nil {d.Close();return nil,nil,errors.New("configuration")}
    if err=d.Up();err!=nil{d.Close();return nil,nil,errors.New("start")}
    nic,err:=net.InterfaceByName(in.Interface);if err!=nil{d.Close();return nil,nil,errors.New("transport interface")}
    peek,ok:=b.(conn.PeekLookAtSocketFd);if !ok{d.Close();return nil,nil,errors.New("transport binding")}
    fd,err:=peek.PeekLookAtSocketFd4();if err!=nil{d.Close();return nil,nil,errors.New("transport socket")}
    index:=uint32(nic.Index);networkOrder:=(index&255)<<24|(index&65280)<<8|(index&16711680)>>8|index>>24
    if err=windows.SetsockoptInt(windows.Handle(fd),windows.IPPROTO_IP,31,int(networkOrder));err!=nil{d.Close();return nil,nil,errors.New("transport protection")}
    return d,stack,nil
}
func probe(ctx context.Context,stack *netstack.Net,expected string)error{
    tr:=&http.Transport{DialContext:func(c context.Context,n,a string)(net.Conn,error){return stack.DialContext(c,"tcp4",a)},TLSHandshakeTimeout:10*time.Second}
    defer tr.CloseIdleConnections()
    req,_:=http.NewRequestWithContext(ctx,"GET","https://api.ipify.org",nil)
    response,err:=(&http.Client{Transport:tr,Timeout:20*time.Second}).Do(req);if err!=nil{return errors.New("https")}
    defer response.Body.Close();bytes,err:=io.ReadAll(io.LimitReader(response.Body,65));if err!=nil{return errors.New("read")}
    if strings.TrimSpace(string(bytes))!=expected{return errors.New("egress")};return nil
}
func probeUDP(ctx context.Context,a *awgOutbound)error{
    destination:=&net.UDPAddr{IP:net.IPv4(1,1,1,1),Port:53}
    packet,err:=a.ListenPacket(ctx,M.SocksaddrFromNet(destination));if err!=nil{return errors.New("udp-listen")};defer packet.Close()
    deadline:=time.Now().Add(8*time.Second);if end,ok:=ctx.Deadline();ok&&end.Before(deadline){deadline=end}
    if err=packet.SetDeadline(deadline);err!=nil{return errors.New("udp-deadline")}
    query:=dnsmessage.Message{Header:dnsmessage.Header{ID:0x1314,RecursionDesired:true},Questions:[]dnsmessage.Question{{Name:dnsmessage.MustNewName("api.ipify.org."),Type:dnsmessage.TypeA,Class:dnsmessage.ClassINET}}}
    data,err:=query.Pack();if err!=nil{return errors.New("udp-query")}
    if _,err=packet.WriteTo(data,destination);err!=nil{return errors.New("udp-write")}
    buffer:=make([]byte,4096);n,from,err:=packet.ReadFrom(buffer);if err!=nil{return errors.New("udp-read")}
    if from.String()!=destination.String(){return errors.New("udp-source")}
    var response dnsmessage.Message
    if response.Unpack(buffer[:n])!=nil||!response.Header.Response||response.Header.ID!=query.Header.ID||response.Header.RCode!=dnsmessage.RCodeSuccess||len(response.Answers)==0{return errors.New("udp-reply")}
    return nil
}

func run()error{
    if len(os.Args)!=2 {return errors.New("arguments")}
    mode:=os.Args[1];if mode!="--check"&&mode!="--probe"&&mode!="--run"&&mode!="--proxy-test"{return errors.New("arguments")}
    // Profile and keys enter only through the inherited anonymous pipe, never argv or a file.
    reader:=bufio.NewReaderSize(os.Stdin,262144)
    line,err:=reader.ReadString('\n');if err!=nil||len(line)>200000{return errors.New("input")}
    var in Input;dec:=json.NewDecoder(strings.NewReader(line));dec.DisallowUnknownFields();if dec.Decode(&in)!=nil{return errors.New("input")}
    if !validLifetime(mode,in.Seconds)||len(in.UAPI)>65536||strings.ContainsRune(in.UAPI,'\x00'){return errors.New("limits")}
    a:=&awgOutbound{};ctx,opt,err:=options(in,a,mode=="--proxy-test");if err!=nil{return errors.New("rules")}
    if mode=="--check"{event("checked",nil);return nil}
    if mode=="--run"&&!windows.GetCurrentProcessToken().IsElevated(){return errors.New("administrator")}
    stop:=make(chan struct{})
    go func(){_,_=reader.ReadString('\n');close(stop)}() // stop command, EOF, or parent death all stop the engine.
    ctx,cancel:=sessionContext(ctx,stop,time.Duration(in.Seconds)*time.Second);defer cancel()
    d,stack,err:=startAWG(in);if err!=nil{return errors.New("awg")};defer d.Close();a.stack=stack;a.address=netip.MustParseAddr(in.Address)
    event("transport-started",nil)
    if err=probe(ctx,stack,in.ExpectedIP);err!=nil{return errors.New("vpn-check")}
    event("vpn-verified",obj{"ip":in.ExpectedIP})
    if err=probeUDP(ctx,a);err!=nil{return err}
    event("udp-verified",nil)
    if mode=="--probe"{return nil}
    instance,err:=box.New(box.Options{Options:opt,Context:ctx});if err!=nil{return errors.New("router-create")}
    defer instance.Close()
    if err=instance.Start();err!=nil{return errors.New("router-start")}
    event("ready",obj{"seconds":in.Seconds,"mode":in.Rules.Mode})
    if mode=="--run"{go systemChecks(ctx,in.ExpectedIP)}
    <-ctx.Done()
    event("stopping",obj{"vpn_connections":a.count.Load(),"vpn_web_connections":a.web.Load()})
    return nil
}
// These probes use Windows DNS and the actual OS TUN route, unlike the
// preflight probe above, which deliberately tests AWG before changing routes.
func systemChecks(ctx context.Context,expected string){
    select{case <-time.After(time.Second):case <-ctx.Done():return}
    for i,domain:=range []string{"api.ipify.org","api4.ipify.org"}{
        label:=[]string{"selected","other"}[i]
        c,cancel:=context.WithTimeout(ctx,15*time.Second)
        addresses,err:=net.DefaultResolver.LookupIP(c,"ip4",domain)
        if err!=nil{event("system-dns-"+label+"-failed",nil);cancel();continue}
        fake:=false;prefix:=netip.MustParsePrefix("198.18.0.0/15")
        for _,address:=range addresses{if ip,ok:=netip.AddrFromSlice(address);ok&&prefix.Contains(ip.Unmap()){fake=true}}
        kind:="real";if fake{kind="fake"};event("system-dns-"+label+"-"+kind,nil)
        dialer:=&net.Dialer{Timeout:10*time.Second}
        tr:=&http.Transport{DialContext:func(c context.Context,n,a string)(net.Conn,error){return dialer.DialContext(c,"tcp4",a)},TLSHandshakeTimeout:8*time.Second}
        req,_:=http.NewRequestWithContext(c,"GET","https://"+domain,nil)
        response,e:=(&http.Client{Transport:tr,Timeout:12*time.Second}).Do(req)
        result:="failed"
        if e==nil{
            data,readErr:=io.ReadAll(io.LimitReader(response.Body,65));response.Body.Close()
            if readErr==nil&&response.StatusCode==200{
                if ip,parseErr:=netip.ParseAddr(strings.TrimSpace(string(data)));parseErr==nil{
                    result="direct";if ip.String()==expected{result="vpn"}
                }
            }
        }
        event("system-https-"+label+"-"+result,nil)
        tr.CloseIdleConnections();cancel()
    }
}
func main(){
    if err:=run();err!=nil{event("error",obj{"code":err.Error()});os.Exit(1)}
    fmt.Println("{\"event\":\"stopped\"}")
}
