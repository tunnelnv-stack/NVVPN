package main

import (
    "testing"

    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/log"
    "github.com/sagernet/sing-box/route/rule"
    M "github.com/sagernet/sing/common/metadata"
)

// Use sing-box's real matcher, including domain suffix boundaries and rule order.
func TestVideoCompatibilityRouting(t *testing.T) {
    for _,enabled:=range []bool{false,true}{
        in:=validInput();in.Rules=Rules{Mode:"except",Apps:[]string{`C:\Apps\Browser.exe`},Domains:[]string{"vk.com","direct.youtube.com"},Subdomains:true,VideoCompatibility:enabled}
        ctx,opt,err:=options(in,&awgOutbound{},false);if err!=nil{t.Fatal(err)}
        var rules []adapter.Rule
        for _,options:=range opt.Route.Rules{
            if options.DefaultOptions.Action!="route" && options.DefaultOptions.Action!="reject"{continue}
            r,e:=rule.NewRule(ctx,log.NewNOPFactory().Logger(),options,true);if e!=nil{t.Fatal(e)};rules=append(rules,r)
        }
        for _,c:=range []struct{host,network string;port uint16;blocked,direct bool}{
            {"rr1.googlevideo.com","udp",443,true,false},
            {"www.youtube.com","udp",443,true,false},
            {"www.youtube-nocookie.com","udp",443,true,false},
            {"rr1.googlevideo.com","tcp",443,false,false},
            {"rr1.googlevideo.com","udp",444,false,false},
            {"googlevideo.com.attacker.test","udp",443,false,false},
            {"notgooglevideo.com","udp",443,false,false},
            {"example.com","udp",443,false,false},
            {"","udp",443,false,false},
            {"vk.com","udp",443,false,true},
            {"direct.youtube.com","udp",443,false,true},
        }{
            metadata:=adapter.InboundContext{IPVersion:4,Network:c.network,Destination:M.Socksaddr{Fqdn:c.host,Port:c.port}}
            got:="route("+opt.Route.Final+")"
            for _,r:=range rules{metadata.ResetRuleCache();if r.Match(&metadata){got=r.Action().String();break}}
            want:="route(vpn)";if c.direct{want="route(direct)"}else if enabled&&c.blocked{want="reject"}
            if got!=want{t.Fatalf("enabled=%v %s %s:%d: got %s want %s",enabled,c.network,c.host,c.port,got,want)}
        }
        metadata:=adapter.InboundContext{IPVersion:4,Network:"udp",Destination:M.Socksaddr{Fqdn:"rr1.googlevideo.com",Port:443},ProcessInfo:&adapter.ConnectionOwner{ProcessPath:`c:\apps\browser.exe`}}
        got:="route("+opt.Route.Final+")"
        for _,r:=range rules{metadata.ResetRuleCache();if r.Match(&metadata){got=r.Action().String();break}}
        if got!="route(direct)"{t.Fatal("explicit application exception must win over video comparison",got)}
    }
    if (Rules{Mode:"only",Domains:[]string{"youtube.com"},VideoCompatibility:true}).validate()==nil{t.Fatal("legacy inclusion mode has no compatibility contract")}
}
