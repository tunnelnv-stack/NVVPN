package main

import (
    "context"
    "time"
)

// Interactive sessions have no timer. Diagnostic modes retain their hard limit.
func validLifetime(mode string,seconds int) bool {
    if seconds==0{return mode=="--run"||mode=="--check"}
    return seconds>=10&&seconds<=120
}

func sessionContext(parent context.Context,stop <-chan struct{},limit time.Duration)(context.Context,context.CancelFunc){
    ctx,cancel:=context.WithCancel(parent)
    go func(){
        var deadline <-chan time.Time
        if limit>0{timer:=time.NewTimer(limit);defer timer.Stop();deadline=timer.C}
        select{case <-stop:case <-deadline:case <-ctx.Done():}
        cancel()
    }()
    return ctx,cancel
}
