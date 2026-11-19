package main

import (
    "bytes"
    "context"
    "net"
    "net/netip"
    "strconv"
    "sync/atomic"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    box "github.com/sagernet/sing-box"
    "github.com/sagernet/sing-box/option"
    M "github.com/sagernet/sing/common/metadata"
    N "github.com/sagernet/sing/common/network"
    "github.com/sagernet/sing/protocol/socks"
    "golang.org/x/net/dns/dnsmessage"
)

// Exercise the actual SOCKS UDP -> sing-box -> custom AWG outbound path.
// All destination traffic stays in an in-memory netstack. No TUN, OS routes,
// server settings, system DNS or running VPN are changed by this regression.
func TestRouterUDPRoundTripIPAndDomain(t *testing.T) {
    local:=netip.MustParseAddr("10.200.0.2")
    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{local},[]netip.Addr{local},1280)
    if err!=nil{t.Fatal(err)};defer tun.Close()
    echo,err:=stack.ListenUDPAddrPort(netip.AddrPortFrom(local,0))
    if err!=nil{t.Fatal(err)};defer echo.Close()
    go func(){data:=make([]byte,4096);for{n,source,e:=echo.ReadFrom(data);if e!=nil{return};if _,e=echo.WriteTo(data[:n],source);e!=nil{return}}}()
    resolver,err:=stack.ListenUDPAddrPort(netip.AddrPortFrom(local,53))
    if err!=nil{t.Fatal(err)};defer resolver.Close()
    var dnsRequests atomic.Int32
    go func(){
        data:=make([]byte,4096)
        for{
            n,source,e:=resolver.ReadFrom(data);if e!=nil{return}
            var query dnsmessage.Message;if query.Unpack(data[:n])!=nil{continue}
            dnsRequests.Add(1)
            reply:=dnsmessage.Message{Header:dnsmessage.Header{ID:query.Header.ID,Response:true,RecursionDesired:true,RecursionAvailable:true},Questions:query.Questions}
            for _,q:=range query.Questions{if q.Type==dnsmessage.TypeA{reply.Answers=append(reply.Answers,dnsmessage.Resource{Header:dnsmessage.ResourceHeader{Name:q.Name,Type:dnsmessage.TypeA,Class:dnsmessage.ClassINET,TTL:30},Body:&dnsmessage.AResource{A:local.As4()}})}}
            b,e:=reply.Pack();if e==nil{_,_=resolver.WriteTo(b,source)}
        }
    }()
    reserved,err:=net.Listen("tcp4","127.0.0.1:0");if err!=nil{t.Fatal(err)}
    port:=reserved.Addr().(*net.TCPAddr).Port;reserved.Close()
    in:=validInput();in.Interface="";in.DNS=[]string{local.String()};in.Rules=Rules{Mode:"except",Domains:[]string{"vk.com"},Subdomains:true}
    a:=&awgOutbound{stack:stack,address:local}
    ctx,opt,err:=options(in,a,true);if err!=nil{t.Fatal(err)}
    opt.Inbounds[0].Options.(*option.HTTPMixedInboundOptions).ListenPort=uint16(port)
    opt.Log.Disabled=true
    ctx,cancel:=context.WithTimeout(ctx,10*time.Second);defer cancel()
    router,err:=box.New(box.Options{Options:opt,Context:ctx});if err!=nil{t.Fatal(err)};defer router.Close()
    if err=router.Start();err!=nil{t.Fatal(err)}
    proxy:=socks.NewClient(N.SystemDialer,M.ParseSocksaddr(net.JoinHostPort("127.0.0.1",strconv.Itoa(port))),socks.Version5,"","")
    echoPort:=echo.LocalAddr().(*net.UDPAddr).Port
    for _,host:=range []string{local.String(),"udp.test","udp.test"}{
        connection,e:=proxy.DialContext(ctx,"udp",M.ParseSocksaddr(net.JoinHostPort(host,strconv.Itoa(echoPort))))
        if e!=nil{t.Fatal(e)}
        connection.SetDeadline(time.Now().Add(3*time.Second))
        payload:=[]byte("udp-router-regression")
        if _,e=connection.Write(payload);e!=nil{connection.Close();t.Fatal(e)}
        received:=make([]byte,128);n,e:=connection.Read(received);connection.Close()
        if e!=nil||!bytes.Equal(received[:n],payload){t.Fatalf("UDP route %s failed: %v",host,e)}
    }
    if a.count.Load()<2{t.Fatal("UDP did not use the AWG outbound")}
    if dnsRequests.Load()!=1{t.Fatalf("repeated connections should share a cached DNS answer, queries=%d",dnsRequests.Load())}
}
