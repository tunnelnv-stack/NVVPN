package main

import (
    "context"
    "testing"
    "time"
)

func TestConnectionLifetime(t *testing.T){
    if !validLifetime("--run",0)||!validLifetime("--check",0)||validLifetime("--proxy-test",0)||validLifetime("--probe",0)||validLifetime("--run",-1)||validLifetime("--run",121){t.Fatal("lifetime limits")}
    stop:=make(chan struct{});ctx,cancel:=sessionContext(context.Background(),stop,0);defer cancel()
    select{case <-ctx.Done():t.Fatal("interactive connection stopped without a request");case <-time.After(30*time.Millisecond):}
    close(stop)
    select{case <-ctx.Done():case <-time.After(time.Second):t.Fatal("stdin stop did not cancel interactive session")}
    timed,release:=sessionContext(context.Background(),make(chan struct{}),20*time.Millisecond);defer release()
    select{case <-timed.Done():case <-time.After(time.Second):t.Fatal("diagnostic deadline did not fire")}
    parent,end:=context.WithCancel(context.Background());child,closeChild:=sessionContext(parent,make(chan struct{}),0);defer closeChild();end()
    select{case <-child.Done():case <-time.After(time.Second):t.Fatal("parent cancellation ignored")}
}
