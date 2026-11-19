package main

import (
    "encoding/json"
    "strings"
    "testing"
)

func validInput() Input {return Input{Endpoint:"192.0.2.1:8443",Interface:"Ethernet",Rules:Rules{Mode:"all"},Seconds:120}}
func TestModesAndConfig(t *testing.T){
    for _,mode:=range []string{"all","except","only"}{
        in:=validInput();in.Rules=Rules{Mode:mode,Apps:[]string{`C:\Apps\Browser.exe`},Domains:[]string{"example.com"},Subdomains:true}
        ctx,opt,err:=options(in,&awgOutbound{},false);_ = ctx
        if err!=nil{t.Fatalf("config %s: %v",mode,err)}
        if len(opt.Inbounds)!=1||len(opt.Outbounds)!=2{t.Fatal("missing components")}
        b,_:=routerConfig(in,false);var o map[string]any;_ = json.Unmarshal(b,&o)
        r:=o["route"].(map[string]any);expected:="vpn";if mode=="only"{expected="direct"}
        if r["final"]!=expected{t.Fatal("wrong default")}
        if r["find_process"]!=true{t.Fatal("application rules need process lookup")}
        text:=string(b)
        if mode!="all"&&!strings.Contains(text,"process_path_regex"){t.Fatal("missing exact case-insensitive process matching")}
        if mode!="all"&&!strings.Contains(text,"domain_suffix"){t.Fatal("missing subdomain match")}
        if !strings.Contains(text,`"ip_version":6`){t.Fatal("missing IPv6 block")}
        if !strings.Contains(text,`"stack":"gvisor"`){t.Fatal("Windows test must not depend on a native inbound TCP firewall exception")}
        if strings.Contains(text,"private_key"){t.Fatal("secret in routing config")}
    }
}
func TestInvalidRules(t *testing.T){
    for _,domain:=range []string{"https://example.com","example.com/a","*.example.com","com","127.0.0.1","-a.com","a..com","EXAMPLE.com","a.com\nexample.net"}{
        r:=Rules{Mode:"only",Domains:[]string{domain}};if r.validate()==nil{t.Fatal("accepted invalid domain")}
    }
    for _,app:=range []string{"browser.exe",`C:\a.cmd`,"C:\\bad\n.exe"}{
        if (Rules{Mode:"except",Apps:[]string{app}}).validate()==nil{t.Fatal("accepted invalid application")}
    }
    if (Rules{Mode:"only"}).validate()==nil{t.Fatal("empty only list")}
    if (Rules{Mode:"invalid"}).validate()==nil{t.Fatal("invalid mode")}
}
func TestExactDomainsAndNoTunForProxyTest(t *testing.T){
    in:=validInput();in.Rules=Rules{Mode:"only",Domains:[]string{"example.com"}}
    b,err:=routerConfig(in,true);if err!=nil{t.Fatal(err)}
    s:=string(b);if strings.Contains(s,"domain_suffix")||strings.Contains(s,`"auto_route"`){t.Fatal("scope broadened")}
    if !strings.Contains(s,`"domain":["example.com"]`){t.Fatal("no exact rule")}
}
func TestExclusionsProtectDefaultAndUnknownSites(t *testing.T){
    for _,domains:=range [][]string{nil,{"example.com"}}{
        in:=validInput();in.Rules=Rules{Mode:"except",Domains:domains}
        _,opt,err:=options(in,&awgOutbound{},false)
        if err!=nil{t.Fatal(err)}
        if opt.Route.Final!="vpn"{t.Fatal("unlisted traffic must stay on VPN")}
        if opt.Route.FindProcess{t.Fatal("process lookup should be disabled without application exceptions")}
        selected,other:=in.Rules.destinations();if selected!="direct"||other!="vpn"{t.Fatal("exception actions inverted")}
        b,_:=routerConfig(in,false)
        if strings.Contains(string(b),`"domain_regex"`){t.Fatal("unidentified sites must retain VPN default")}
    }
}
