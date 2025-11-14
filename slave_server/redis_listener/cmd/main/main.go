package main

import (
    "log"
    "netsimlation/distribute/slave_server/redis_listener/internal/config"
    "netsimlation/distribute/slave_server/redis_listener/internal/daemon"
    "netsimlation/distribute/slave_server/redis_listener/internal/signal"
)

func main() {
    // 加载配置
    cfg, err := config.Load("configs/config.yaml")
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 创建带有信号处理的上下文
    ctx, stop := signal.NotifyContext()
    defer stop()

    // 创建并运行守护进程
    d := daemon.NewDaemon(cfg)
    
    if err := d.Run(ctx); err != nil {
        log.Fatalf("Daemon run failed: %v", err)
    }
    
    log.Println("Redis bridge daemon stopped gracefully")
}