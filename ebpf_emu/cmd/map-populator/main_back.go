package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

// HANDLE_BPS map value struct
type handleBpsDelay struct {
	TcHandle        uint32
	ThrottleRateBps uint32
	DelayMs         uint32
}

// parseIp parses IP address from string into uint32 (with reversed order)
func parseIpToLong(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.LittleEndian, &long)
	return long
}

// parseLongToIp parses uint32 IP address back to string format
func parseLongToIp(ipLong uint32) string {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.LittleEndian, ipLong)
	if err != nil {
		return "invalid_ip"
	}
	ip := net.IP(buffer.Bytes()).String()
	return ip
}

// printMap iterates through the eBPF map and prints all entries
func printMap(ebpfMap *ebpf.Map) {
	var count int

	// Create an iterator for the map
	iter := ebpfMap.Iterate()
	var key uint32
	var value handleBpsDelay

	// Print table header
	fmt.Println("\nIP Address\t\tTC Handle\tBandwidth (Mbps)\tDelay (ms)")
	fmt.Println("-----------------------------------------------------------")

	// Iterate through all entries
	for iter.Next(&key, &value) {
		count++
		ip := parseLongToIp(key)
		bandwidthMbps := float64(value.ThrottleRateBps) / 1000000.0
		fmt.Printf("%s\t\t0x%x\t\t%.2f\t\t%d\n", ip, value.TcHandle, bandwidthMbps, value.DelayMs)
	}

	// Check for iteration errors
	if err := iter.Err(); err != nil {
		fmt.Printf("Error iterating map: %v\n", err)
	}

	fmt.Printf("\nTotal entries in map: %d\n", count)
}

// clearMap removes all entries from the eBPF map
func clearMap(ebpfMap *ebpf.Map) error {
	var count int

	// Create an iterator for the map
	iter := ebpfMap.Iterate()
	var key uint32
	var value handleBpsDelay

	// Iterate through all entries and delete them
	for iter.Next(&key, &value) {
		if err := ebpfMap.Delete(key); err != nil {
			return fmt.Errorf("error deleting key %d: %v", key, err)
		}
		count++
	}

	// Check for iteration errors
	if err := iter.Err(); err != nil {
		return fmt.Errorf("error iterating map: %v", err)
	}

	fmt.Printf("Successfully cleared %d entries from the map\n", count)
	return nil
}

// addMapEntry adds a single entry to the eBPF map
func addMapEntry(ebpfMap *ebpf.Map, ip string, tcHandle uint32, throttleRateBps uint32, delayMs uint32) error {
	// Convert IP to long format
	key := parseIpToLong(ip)
	
	// Create value struct
	value := handleBpsDelay{
		TcHandle:        tcHandle,
		ThrottleRateBps: throttleRateBps,
		DelayMs:         delayMs,
	}
	
	// Update the map
	if err := ebpfMap.Put(key, value); err != nil {
		return fmt.Errorf("error adding entry for IP %s: %v", ip, err)
	}
	
	fmt.Printf("Successfully added entry for IP %s (TC: 0x%x, Bandwidth: %.2f Mbps, Delay: %d ms)\n",
		ip, tcHandle, float64(throttleRateBps)/1000000.0, delayMs)
	return nil
}

func main() {
	// 操作模式：view（查看）、clear（清空）、add（添加）
	var mode string
	var unpinMap bool
	
	// 添加条目参数
	var ip string
	var tcHandle uint
	var bandwidthMbps uint
	var delayMs uint

	flag.StringVar(&mode, "mode", "view", "Operation mode: view (查看表), clear (清空表), add (添加表)")
	flag.BoolVar(&unpinMap, "unpin-map", false, "Unpins the map and exits")
	flag.StringVar(&ip, "ip", "", "IP address to add (required for add mode)")
	flag.UintVar(&tcHandle, "tc-handle", 0, "TC handle value (required for add mode)")
	flag.UintVar(&bandwidthMbps, "bandwidth", 0, "Bandwidth in Mbps (required for add mode)")
	flag.UintVar(&delayMs, "delay", 0, "Delay in ms (required for add mode)")

	flag.Parse()

	// Path to the map file of the eBPF program
	ebpfMapFile := "/sys/fs/bpf/IP_HANDLE_BPS_DELAY"

	// Load map
	ipHandleMap, err := ebpf.LoadPinnedMap(ebpfMapFile, &ebpf.LoadPinOptions{})
	if err != nil {
		fmt.Println("错误: 加载映射文件失败")
		fmt.Println(err)
		os.Exit(1)
	}

	// Check if map should be unpinned
	if unpinMap {
		err = ipHandleMap.Unpin()
		if err != nil {
			fmt.Println("错误: 无法解除映射")
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("映射解除成功")
		os.Exit(0)
	}

	// Print map info
	fmt.Printf("加载的映射: %+v\n", ipHandleMap)
	fmt.Printf("映射类型: %s\n", ipHandleMap.Type())
	fmt.Printf("最大条目数: %d\n", ipHandleMap.MaxEntries())

	// 根据模式执行相应操作
	switch mode {
	case "view":
		printMap(ipHandleMap)
		
	case "clear":
		if err := clearMap(ipHandleMap); err != nil {
			fmt.Printf("错误: 清空表失败: %v\n", err)
			os.Exit(1)
		}
		
	case "add":
		// 验证添加模式所需的参数
		if ip == "" || tcHandle == 0 || bandwidthMbps == 0 || delayMs == 0 {
			fmt.Println("错误: 添加模式需要提供以下参数: -ip, -tc-handle, -bandwidth, -delay")
			fmt.Println("用法示例: sudo go run main.go -mode add -ip 192.168.1.1 -tc-handle 100 -bandwidth 10 -delay 50")
			os.Exit(1)
		}
		
		// 转换带宽从Mbps到Bps
		throttleRateBps := bandwidthMbps * 1000000
		
		if err := addMapEntry(ipHandleMap, ip, uint32(tcHandle), uint32(throttleRateBps), uint32(delayMs)); err != nil {
			fmt.Printf("错误: 添加表条目失败: %v\n", err)
			os.Exit(1)
		}
		
	default:
		fmt.Println("错误: 无效的操作模式。可用模式: view, clear, add")
		fmt.Println("用法示例:")
		fmt.Println("  查看表: sudo go run main.go -mode view")
		fmt.Println("  清空表: sudo go run main.go -mode clear")
		fmt.Println("  添加表: sudo go run main.go -mode add -ip 192.168.1.1 -tc-handle 100 -bandwidth 10 -delay 50")
		os.Exit(1)
	}
}
