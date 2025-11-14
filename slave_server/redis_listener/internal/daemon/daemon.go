package daemon

import (
    "context"
    "log"
    "time"

    "netsimlation/distribute/slave_server/redis_listener/internal/config"
    "netsimlation/distribute/slave_server/redis_listener/internal/redis"
)

type Daemon struct {
    config *config.Config
}

func NewDaemon(cfg *config.Config) *Daemon {
    return &Daemon{
        config: cfg,
    }
}

func (d *Daemon) Run(ctx context.Context) error {
    log.Printf("启动 %s v%s", d.config.App.Name, d.config.App.Version)
    
    subscriber := redis.NewSubscriber(&d.config.Redis)
    defer subscriber.Close()

    // 启动Redis订阅
    errCh := make(chan error, 1)
    
    go func() {
        if err := subscriber.Subscribe(ctx, d.handleKeyEvent); err != nil {
            errCh <- err
        }
    }()

    // 等待上下文取消或错误
    select {
    case err := <-errCh:
        return err
    case <-ctx.Done():
        log.Println("接收到关闭信号，开始优雅关闭...")
        
        // 等待处理中的事件完成
        time.Sleep(2 * time.Second)
        return nil
    }
}

func (d *Daemon) handleKeyEvent(event redis.KeyEvent) {
    // 这里是核心处理逻辑 - 打印到日志
    switch event.EventType {
    case "set":
        log.Printf("SET事件 - 键: %s, 值: %s, 时间: %s", 
            event.Key, event.Value, event.Timestamp.Format(time.RFC3339))
    case "del":
        log.Printf("DEL事件 - 键: %s, 时间: %s", 
            event.Key, event.Timestamp.Format(time.RFC3339))
    case "expired":
        log.Printf("EXPIRED事件 - 键: %s, 时间: %s", 
            event.Key, event.Timestamp.Format(time.RFC3339))
    default:
        log.Printf("未知事件类型 %s - 键: %s", event.EventType, event.Key)
    }
}