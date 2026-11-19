package main

import (
    "encoding/json"
    "errors"
    "net/netip"
    "path/filepath"
    "regexp"
    "strings"
)

type Rules struct {
    Mode string `json:"mode"`
    Apps []string `json:"apps"`
    Domains []string `json:"domains"`
    Subdomains bool `json:"subdomains"`
    VideoCompatibility bool `json:"video_compatibility"`
}
type Input struct {
    Address string `json:"address"`
    DNS []string `json:"dns"`
    Endpoint string `json:"endpoint"`
    ExpectedIP string `json:"expected_ip"`
    UAPI string `json:"uapi"`
    Interface string `json:"interface"`
    Rules Rules `json:"rules"`
    Seconds int `json:"seconds"`
    CachePath string `json:"cache_path,omitempty"`
}
type obj = map[string]any

func (r Rules) validate() error {
    if r.Mode!="all" && r.Mode!="except" && r.Mode!="only" {return errors.New("mode")}
    if r.VideoCompatibility && r.Mode=="only" {return errors.New("video compatibility requires VPN default")}
    if len(r.Apps)>100 || len(r.Domains)>200 {return errors.New("limit")}
    for _,p:=range r.Apps {
        if !filepath.IsAbs(p) || !strings.EqualFold(filepath.Ext(p),".exe") || strings.ContainsAny(p,"\r\n\x00") {return errors.New("app")}
    }
    for _,d:=range r.Domains {
        if len(d)>253 || len(d)<3 || d!=strings.ToLower(d) || !strings.Contains(d,".") || strings.ContainsAny(d,"/:*\\@ \t\r\n\x00") {return errors.New("domain")}
        if _,err:=netip.ParseAddr(d);err==nil {return errors.New("domain is IP")}
        for _,label:=range strings.Split(d,".") {
            if len(label)<1||len(label)>63||label[0]=='-'||label[len(label)-1]=='-' {return errors.New("label")}
            for _,c:=range label {if !(c>='a'&&c<='z'||c>='0'&&c<='9'||c=='-'){return errors.New("ascii domain")}}
        }
    }
    if r.Mode=="only"&&len(r.Apps)+len(r.Domains)==0 {return errors.New("empty selection")}
    return nil
}

// Apps and domains form a union. A matching item always gets the selected-list action.
func (r Rules) destinations()(string,string){if r.Mode=="only"{return "vpn","direct"};return "direct","vpn"}

func routerConfig(in Input, proxyOnly bool) ([]byte,error) {
    if err:=in.Rules.validate();err!=nil{return nil,err}
    selected,other:=in.Rules.destinations()
    rr:=[]obj{
        {"action":"sniff","timeout":"300ms"},
        {"protocol":"dns","action":"hijack-dns"},
        {"ip_version":6,"action":"reject"},
        {"action":"resolve","server":"remote","strategy":"ipv4_only"},
    }
    if in.Rules.Mode!="all" {
        if len(in.Rules.Apps)>0 {
            paths:=[]string{};for _,p:=range in.Rules.Apps{paths=append(paths,"(?i)^"+regexp.QuoteMeta(p)+"$")}
            rr=append(rr,obj{"process_path_regex":paths,"action":"route","outbound":selected})
        }
        if len(in.Rules.Domains)>0 {
            key:="domain";if in.Rules.Subdomains{key="domain_suffix"}
            rr=append(rr,obj{key:in.Rules.Domains,"action":"route","outbound":selected})
            // In exception mode an unidentified destination keeps the protected
            // VPN default. Only the legacy inclusion mode needs a fail-closed block.
            if in.Rules.Mode=="only"{rr=append(rr,obj{"type":"logical","mode":"and","rules":[]obj{{"port":[]int{80,443}},{"domain_regex":[]string{".+"},"invert":true}},"action":"reject"})}
        }
    }
    // Only the test's YouTube destinations lose UDP/443. Explicit direct
    // exceptions above win; TCP and every other destination retain their route.
    if in.Rules.VideoCompatibility {
        rr=append(rr,obj{"network":"udp","port":443,"domain_suffix":[]string{"youtube.com","googlevideo.com","youtube-nocookie.com"},"action":"reject","no_drop":true})
    }
    var ins []obj
    if proxyOnly {
        ins=[]obj{{"type":"mixed","tag":"test-in","listen":"127.0.0.1","listen_port":39391}}
    }else{
        ins=[]obj{{"type":"tun","tag":"desktop","interface_name":"NeverVPN","address":[]string{"172.31.253.1/30","fdfe:1314:5350::1/126"},"mtu":1280,"auto_route":true,"strict_route":true,"dns_mode":"hijack","stack":"gvisor","route_exclude_address":[]string{strings.Split(in.Endpoint,":")[0]+"/32"}}}
    }
    // Resolve all names through encrypted AWG transport. Direct means direct payload, not direct DNS.
    dnsServer:="1.1.1.1";if len(in.DNS)>0{dnsServer=in.DNS[0]}
    config:=obj{
        // stderr is an inherited anonymous pipe. The controller records only fixed
        // diagnostic categories and counts; raw messages are discarded in memory.
        "log":obj{"level":"debug","disabled":false},
        "dns":obj{"servers":[]obj{
            {"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
            {"type":"udp","tag":"remote","server":dnsServer,"server_port":53,"detour":"vpn"},
        },"rules":[]obj{{"query_type":[]string{"A","AAAA"},"action":"route","server":"fake"}},"final":"remote","strategy":"ipv4_only"},
        "inbounds":ins,
        "outbounds":[]obj{
            {"type":"finland-awg","tag":"vpn"},
            {"type":"direct","tag":"direct","bind_interface":in.Interface,"domain_resolver":obj{"server":"remote","strategy":"ipv4_only"}},
        },
        "route":obj{"rules":rr,"final":other,"find_process":len(in.Rules.Apps)>0,"default_interface":in.Interface,"default_domain_resolver":obj{"server":"remote","strategy":"ipv4_only"}},
    }
    if in.CachePath!=""{
        if !filepath.IsAbs(in.CachePath){return nil,errors.New("cache path")}
        config["experimental"]=obj{"cache_file":obj{"enabled":true,"path":in.CachePath,"store_fakeip":true}}
    }
    return json.Marshal(config)
}
