package main

import (
    "context"
    "net/netip"
    "path/filepath"
    "testing"

    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/dns/transport/fakeip"
    "github.com/sagernet/sing-box/experimental/cachefile"
    "github.com/sagernet/sing-box/log"
    "github.com/sagernet/sing/service"
)

func TestFakeIPSurvivesRestart(t *testing.T){
    in:=validInput();in.CachePath=filepath.Join(t.TempDir(),"router.db")
    _,opt,err:=options(in,&awgOutbound{},true);if err!=nil{t.Fatal(err)}
    if opt.Experimental==nil||opt.Experimental.CacheFile==nil||!opt.Experimental.CacheFile.StoreFakeIP{t.Fatal("FakeIP persistence is not configured")}
    logger:=log.NewNOPFactory().Logger()
    var first netip.Addr
    for run:=0;run<2;run++{
        ctx:=context.Background();scope:=adapter.NewScope(ctx,logger)
        disk:=cachefile.New(ctx,logger,*opt.Experimental.CacheFile)
        if err=disk.Start(adapter.StartStateInitialize,scope);err!=nil{t.Fatal(err)}
        store:=fakeip.NewStore(service.ContextWith[adapter.CacheFile](ctx,disk),logger,netip.MustParsePrefix("198.18.0.0/15"),netip.Prefix{})
        if err=store.Start();err!=nil{scope.Close();t.Fatal(err)}
        if run==0{
            first,err=store.Create("first.test",false)
        }else{
            domain,found:=store.Lookup(first)
            if !found||domain!="first.test"{store.Close();scope.Close();t.Fatal("mapping lost after restart")}
            var again,next netip.Addr
            again,err=store.Create("first.test",false)
            if err==nil{next,err=store.Create("second.test",false)}
            if again!=first||next==first{store.Close();scope.Close();t.Fatal("cached addresses were reassigned")}
        }
        if err!=nil{store.Close();scope.Close();t.Fatal(err)}
        if err=store.Close();err!=nil{scope.Close();t.Fatal(err)}
        if err=scope.Close();err!=nil{t.Fatal(err)}
    }
}
