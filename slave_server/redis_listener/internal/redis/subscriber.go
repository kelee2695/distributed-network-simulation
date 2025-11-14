package redis

import (
    "context"
    "log"
    "strings"
    "time"

    "github.com/go-redis/redis/v8"
    "netsimlation/distribute/slave_server/redis_listener/internal/config"
)

type Subscriber struct {
    client    *redis.Client
    config    *config.RedisConfig
    isRunning bool
}

type KeyEvent struct {
    EventType string    `json:"event_type"` // set, del, expired
    Key       string    `json:"key"`
    Value     string    `json:"value,omitempty"`
    Timestamp time.Time `json:"timestamp"`
}

type EventHandler func(event KeyEvent)

func NewSubscriber(cfg *config.RedisConfig) *Subscriber {
    return &Subscriber{
        client: redis.NewClient(&redis.Options{
            Addr:     cfg.Addr,
            Password: cfg.Password,
            DB:       cfg.DB,
        }),
        config: cfg,
    }
}

func (s *Subscriber) Subscribe(ctx context.Context, handler EventHandler) error {
    // 测试Redis连接
    if err := s.client.Ping(ctx).Err(); err != nil {
        return err
    }

    // 创建发布订阅
    pubsub := s.client.PSubscribe(ctx, s.config.KeyPatterns...)
    defer pubsub.Close()

    s.isRunning = true
    log.Printf("开始监听Redis键空间事件: %v", s.config.KeyPatterns)

    // 处理消息通道
    for {
        select {
        case <-ctx.Done():
            s.isRunning = false
            log.Println("停止监听Redis事件")
            return nil
            
        case msg, ok := <-pubsub.Channel():
            if !ok {
                return nil
            }
            go s.handleMessage(ctx, msg, handler)
        }
    }
}

func (s *Subscriber) handleMessage(ctx context.Context, msg *redis.Message, handler EventHandler) {
    // 解析频道获取事件类型
    channelParts := strings.Split(msg.Channel, ":")
    if len(channelParts) < 2 {
        return
    }
    
    eventType := channelParts[1]
    keyName := msg.Payload

    // 键前缀过滤
    if !s.shouldProcessKey(keyName) {
        return
    }
    log.Printf("收到事件 - 键: %s, 事件类型: %s", keyName, eventType)

    event := KeyEvent{
        EventType: eventType,
        Key:       keyName,
        Timestamp: time.Now(),
    }

    // 对于set事件，获取键的值
    if eventType == "set" {
        value, err := s.client.Get(ctx, keyName).Result()
        if err == nil {
            event.Value = value
        } else {
            log.Printf("获取键值失败 %s: %v", keyName, err)
        }
    }

    // 调用事件处理器
    handler(event)
}

func (s *Subscriber) shouldProcessKey(key string) bool {
    if len(s.config.KeyPrefixes) == 0 {
        return true
    }
    
    for _, prefix := range s.config.KeyPrefixes {
        if strings.HasPrefix(key, prefix) {
            return true
        }
    }
    return false
}

func (s *Subscriber) Close() error {
    s.isRunning = false
    return s.client.Close()
}