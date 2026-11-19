package main

import (
    "bytes"
    "context"
    "fmt"
    "net"
    "net/netip"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun"
    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    M "github.com/sagernet/sing/common/metadata"
)

// Two in-memory IP stacks joined at the same MTU as the actual AWG transport.
// Unlike same-stack loopback, this exercises IPv4 fragmentation/reassembly.
// Nothing is installed in the OS and no external connection is made.
func TestAWGUDPAcrossMTUBoundary(t *testing.T) {
    left:=netip.MustParseAddr("10.200.0.2");right:=netip.MustParseAddr("10.200.0.3")
    lt,ls,e:=netstack.CreateNetTUN([]netip.Addr{left},nil,1280);if e!=nil{t.Fatal(e)}
    rt,rs,e:=netstack.CreateNetTUN([]netip.Addr{right},nil,1280);if e!=nil{lt.Close();t.Fatal(e)}
    done:=make(chan struct{},2)
    pump:=func(src,dst tun.Device){
        defer func(){done<-struct{}{}}()
        packet:=make([]byte,65536);sizes:=make([]int,1)
        for {_,err:=src.Read([][]byte{packet},sizes,0);if err!=nil{return};if _,err=dst.Write([][]byte{packet[:sizes[0]]},0);err!=nil{return}}
    }
    go pump(lt,rt);go pump(rt,lt)
    defer func(){lt.Close();rt.Close();for i:=0;i<2;i++{select{case <-done:case <-time.After(2*time.Second):t.Error("packet pump did not stop")}}}()
    a:=&awgOutbound{stack:ls,address:left}
    client,e:=a.ListenPacket(context.Background(),M.ParseSocksaddr("10.200.0.3:9"));if e!=nil{t.Fatal(e)};defer client.Close()
    server,e:=rs.ListenUDPAddrPort(netip.AddrPortFrom(right,0));if e!=nil{t.Fatal(e)};defer server.Close()
    target:=server.LocalAddr().(*net.UDPAddr)
    for _,size:=range []int{1200,1252,1280,1350,1452,4096}{
        t.Run(fmt.Sprint(size),func(t *testing.T){
            payload:=bytes.Repeat([]byte{0x5a},size);received:=make([]byte,8192)
            client.SetDeadline(time.Now().Add(time.Second));server.SetDeadline(time.Now().Add(time.Second))
            if _,e=client.WriteTo(payload,target);e!=nil{t.Fatal("send",e)}
            n,source,err:=server.ReadFrom(received);if err!=nil||!bytes.Equal(payload,received[:n]){t.Fatal("receive",err)}
            if _,err=server.WriteTo(payload,source);err!=nil{t.Fatal("reply",err)}
            n,_,err=client.ReadFrom(received);if err!=nil||!bytes.Equal(payload,received[:n]){t.Fatal("return",err)}
        })
    }
}
