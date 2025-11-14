package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/go-redis/redis/v8"
)

// NetworkLink 定义网络链路结构体
type NetworkLink struct {
	SourceMAC     string  `json:"source_mac"`      // 源MAC地址
	DestNodeID    int     `json:"dest_node_id"`    // 目的节点ID
	PacketLossRate float64 `json:"packet_loss_rate"` // 链路丢包率（0.0-1.0）
	BandwidthBps  uint64  `json:"bandwidth_bps"`   // 链路带宽（bps）
	DelayMs       uint32  `json:"delay_ms"`        // 链路延迟（毫秒）
	CreatedAt     string  `json:"created_at"`      // 创建时间
}

func main() {
	// Redis连接参数
	redisAddr := "localhost:6379"
	redisPassword := "" // 默认无密码
	redisDB := 0        // 默认数据库

	// 创建Redis客户端
	client := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
		// 添加连接池配置
		PoolSize:     10,
		MinIdleConns: 5,
		// 添加超时设置
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolTimeout:  4 * time.Second,
	})
	defer client.Close()

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 验证连接
	_, err := client.Ping(ctx).Result()
	if err != nil {
		log.Printf("错误: 无法连接到Redis服务器 %s", redisAddr)
		if err == context.DeadlineExceeded {
			log.Fatalf("连接超时，请检查Redis服务是否运行以及网络连接")
		} else {
			log.Fatalf("连接失败: %v", err)
		}
	}
	log.Printf("成功连接到Redis服务器: %s", redisAddr)

	// 定义要插入的网络链路结构体数量
	linkCount := 1000
	log.Printf("开始插入 %d 个网络链路结构体到Redis...", linkCount)

	// 初始化随机数生成器
	rand.Seed(time.Now().UnixNano())

	// 开始计时
	startTime := time.Now()

	// 使用管道批处理以提高性能
	pipe := client.Pipeline()
	successCount := 0
	errorCount := 0

	for i := 0; i < linkCount; i++ {
		// 生成网络链路结构体
		link := NetworkLink{
			SourceMAC:     generateRandomMAC(),
			DestNodeID:    rand.Intn(1000) + 1,           // 随机节点ID 1-1000
			PacketLossRate: rand.Float64() * 0.1,          // 随机丢包率 0-10%
			BandwidthBps:  uint64(rand.Intn(100)+1) * 1000000, // 1-100 Mbps
			DelayMs:       uint32(rand.Intn(100) + 1),     // 1-100 ms延迟
			CreatedAt:     time.Now().Format(time.RFC3339),
		}

		// 将结构体序列化为JSON
		jsonData, err := json.Marshal(link)
		if err != nil {
			log.Printf("序列化结构体失败 (ID: %d): %v", i, err)
			errorCount++
			continue
		}

		// 生成Redis键名
		key := fmt.Sprintf("network_link:%d", i)

		// 在管道中添加SET命令
		pipe.Set(ctx, key, jsonData, 24*time.Hour)

		// 每100个结构体执行一次管道，减少网络往返
		if (i+1)%100 == 0 || i == linkCount-1 {
			// 执行管道中的命令
			results, err := pipe.Exec(ctx)
			if err != nil {
				log.Printf("批量执行失败: %v", err)
				errorCount++
			} else {
				successCount += len(results)
				log.Printf("已插入 %d/%d 个网络链路结构体", i+1, linkCount)
			}
			// 重置管道
			pipe = client.Pipeline()
		}
	}

	// 计算耗时
	duration := time.Since(startTime)

	// 查询并验证部分数据
	log.Println("\n验证插入的数据...")
	for i := 0; i < 5; i++ { // 验证前5个结构体
		key := fmt.Sprintf("network_link:%d", i)
		val, err := client.Get(ctx, key).Result()
		if err != nil {
			log.Printf("查询键 %s 失败: %v", key, err)
		} else {
			// 反序列化回结构体以验证
			var link NetworkLink
			if err := json.Unmarshal([]byte(val), &link); err != nil {
				log.Printf("反序列化键 %s 失败: %v", key, err)
			} else {
				log.Printf("键 %s 的值:", key)
				log.Printf("  源MAC: %s", link.SourceMAC)
				log.Printf("  目的节点ID: %d", link.DestNodeID)
				log.Printf("  丢包率: %.6f", link.PacketLossRate)
				log.Printf("  带宽: %.2f Mbps", float64(link.BandwidthBps)/1000000.0)
				log.Printf("  延迟: %d ms", link.DelayMs)
			}
		}
	}

	// 查询总插入数量
	pattern := "network_link:*"
	keys, err := client.Keys(ctx, pattern).Result()
	if err != nil {
		log.Printf("查询键数量失败: %v", err)
	} else {
		log.Printf("模式 '%s' 匹配到 %d 个键", pattern, len(keys))
	}

	log.Printf("\n操作完成: 成功插入 %d/%d 个网络链路结构体，耗时: %v", successCount, linkCount, duration)

	// 如果有错误，显示错误统计
	if errorCount > 0 {
		log.Printf("警告: 总计有 %d 个结构体处理失败", errorCount)
	}

}

// 可以在这里添加其他Redis操作相关的辅助函数

// generateRandomMAC 生成随机MAC地址
func generateRandomMAC() string {
	mac := make([]byte, 6)
	for i := range mac {
		mac[i] = byte(rand.Intn(256))
	}
	// 确保MAC地址有效（第一个字节最低位为0，表示单播MAC）
	mac[0] &= 0xFE
	// 第一个字节次低位为0，表示非多播MAC
	mac[0] &= 0xFD
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}