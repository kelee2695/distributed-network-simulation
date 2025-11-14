package signal

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
)

// NotifyContext 创建监听系统信号的上下文
func NotifyContext() (context.Context, context.CancelFunc) {
    ctx, cancel := context.WithCancel(context.Background())
    
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
    
    go func() {
        sig := <-sigChan
        log.Printf("Received signal: %v, initiating graceful shutdown...", sig)
        cancel()
        
        // 强制退出保护
        <-ctx.Done()
        log.Printf("Shutdown timeout reached, forcing exit")
        os.Exit(1)
    }()
    
    return ctx, cancel
}