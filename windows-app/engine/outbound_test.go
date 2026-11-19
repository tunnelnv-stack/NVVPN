package main

import (
    "bytes"
    "context"
    "net"
    "net/netip"
    "testing"
    "time"

    "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
    M "github.com/sagernet/sing/common/metadata"
)

func TestUDPListenerUsesIPv4Stack(t *testing.T) {
    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.200.0.2")},nil,1280)
    if err!=nil{t.Fatal(err)}
    defer tun.Close()
    a:=&awgOutbound{stack:stack,address:netip.MustParseAddr("10.200.0.2")}
    packet,err:=a.ListenPacket(context.Background(),M.ParseSocksaddr("10.200.0.1:9"))
    if err!=nil{t.Fatalf("UDP listener failed: %v",err)}
    if packet==nil{t.Fatal("nil UDP listener")}
    defer packet.Close()
    if _,ok:=packet.LocalAddr().(*net.UDPAddr);!ok{t.Fatal("UDP socket expected")}
    server,err:=stack.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.200.0.2"),0))
    if err!=nil{t.Fatal(err)};defer server.Close()
    packet.SetDeadline(time.Now().Add(2*time.Second));server.SetDeadline(time.Now().Add(2*time.Second))
    payload:=[]byte("udp-regression-test")
    target:=server.LocalAddr().(*net.UDPAddr)
    // A standard net.IPv4() returns 16 bytes; the wrapper must normalize it.
    target.IP=net.IPv4(10,200,0,2)
    if _,err=packet.WriteTo(payload,target);err!=nil{t.Fatal(err)}
    buffer:=make([]byte,128);n,source,err:=server.ReadFrom(buffer)
    if err!=nil||!bytes.Equal(buffer[:n],payload){t.Fatal("outbound UDP datagram not delivered",err)}
    if _,err=server.WriteTo(buffer[:n],source);err!=nil{t.Fatal(err)}
    n,_,err=packet.ReadFrom(buffer)
    if err!=nil||!bytes.Equal(buffer[:n],payload){t.Fatal("return UDP datagram not delivered",err)}
    canceled,cancel:=context.WithCancel(context.Background());cancel()
    if c,e:=a.ListenPacket(canceled,M.ParseSocksaddr("10.200.0.1:9"));e==nil||c!=nil{t.Fatal("canceled UDP listener accepted")}
    if _,e:=packet.WriteTo(payload,M.ParseSocksaddr("example.com:443"));e==nil{t.Fatal("unexpected address type must return an error, never panic")}
    p,ip,e:=a.ListenPacketWithDestination(context.Background(),M.ParseSocksaddr("10.200.0.1:9"))
    if e!=nil{t.Fatal(e)};p.Close()
    if ip.String()!="10.200.0.1"{t.Fatal("incorrect UDP destination mapping")}
    mapped:=M.SocksaddrFromNet(&net.UDPAddr{IP:net.IPv4(10,200,0,1),Port:9})
    p,e=a.ListenPacket(context.Background(),mapped);if e!=nil{t.Fatal("IPv4-mapped destination rejected",e)};p.Close()
    if p,e=a.ListenPacket(context.Background(),M.ParseSocksaddr("[2001:db8::1]:9"));e==nil||p!=nil{t.Fatal("IPv6 destination must be rejected")}
}
