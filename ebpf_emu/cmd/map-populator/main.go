package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// 复合键结构体：对应C代码中的flow_key
type flowKey struct {
	Ifindex  uint32  // 网卡接口索引
	SrcMac   [6]byte // 源MAC地址
}

// HANDLE_BPS map value struct
type handleBpsDelay struct {
	TcHandle        uint32
	ThrottleRateBps uint32
	DelayMs         uint32
}

// parseMacToBytes parses MAC address from string into byte array
func parseMacToBytes(mac string) ([]byte, error) {
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, err
	}
	// 确保是6字节的MAC地址
	if len(macAddr) < 6 {
		return nil, fmt.Errorf("invalid MAC address length")
	}
	return macAddr[:6], nil
}

// parseBytesToMac parses byte array back to MAC address string format
func parseBytesToMac(macBytes []byte) string {
	if len(macBytes) < 6 {
		return "invalid_mac"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 
		macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4], macBytes[5])
}

// printMap iterates through the eBPF map and prints all entries
func printMap(ebpfMap *ebpf.Map) {
	var count int

	// Create an iterator for the map
	iter := ebpfMap.Iterate()
	var key flowKey // 使用复合键
	var value handleBpsDelay

	// Print table header
	fmt.Println("\nInterface Index\tMAC Address\t\tTC Handle\tBandwidth (Mbps)\tDelay (ms)")
	fmt.Println("----------------------------------------------------------------------------")

	// Iterate through all entries
	for iter.Next(&key, &value) {
		count++
		mac := parseBytesToMac(key.SrcMac[:])
		bandwidthMbps := float64(value.ThrottleRateBps) / 1000000.0
		fmt.Printf("%d\t\t%s\t\t0x%x\t\t%.2f\t\t%d\n", key.Ifindex, mac, value.TcHandle, bandwidthMbps, value.DelayMs)
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
	var key flowKey // 使用复合键
	var value handleBpsDelay

	// Iterate through all entries and delete them
	for iter.Next(&key, &value) {
		if err := ebpfMap.Delete(key); err != nil {
			return fmt.Errorf("error deleting entry for ifindex %d, MAC %s: %v", 
				key.Ifindex, parseBytesToMac(key.SrcMac[:]), err)
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

// getInterfaceIndex 获取网卡接口索引
func getInterfaceIndex(ifname string) (uint32, error) {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return 0, fmt.Errorf("interface %s not found: %v", ifname, err)
	}
	return uint32(link.Attrs().Index), nil
}

// addMapEntry adds a single entry to the eBPF map
func addMapEntry(ebpfMap *ebpf.Map, ifname string, mac string, tcHandle uint32, throttleRateBps uint32, delayMs uint32) error {
	// 获取网卡接口索引
	ifindex, err := getInterfaceIndex(ifname)
	if err != nil {
		return err
	}
	
	// Convert MAC to byte array
	keyBytes, err := parseMacToBytes(mac)
	if err != nil {
		return fmt.Errorf("invalid MAC address %s: %v", mac, err)
	}
	
	// Create composite key
	var key flowKey
	key.Ifindex = ifindex
	copy(key.SrcMac[:], keyBytes)
	
	// Create value struct
	value := handleBpsDelay{
		TcHandle:        tcHandle,
		ThrottleRateBps: throttleRateBps,
		DelayMs:         delayMs,
	}
	
	// Update the map
	if err := ebpfMap.Put(key, value); err != nil {
		return fmt.Errorf("error adding entry for ifindex %d, MAC %s: %v", ifindex, mac, err)
	}
	
	fmt.Printf("Successfully added entry for ifindex %d, MAC %s (TC: 0x%x, Bandwidth: %.2f Mbps, Delay: %d ms)\n",
		ifindex, mac, tcHandle, float64(throttleRateBps)/1000000.0, delayMs)
	return nil
}

func main() {
	// 操作模式：view（查看）、clear（清空）、add（添加）
	var mode string
	var unpinMap bool
	
	// 添加条目参数
	var ifname string
	var mac string
	var tcHandle uint
	var bandwidthMbps uint
	var delayMs uint

	flag.StringVar(&mode, "mode", "view", "Operation mode: view (查看表), clear (清空表), add (添加表)")
	flag.BoolVar(&unpinMap, "unpin-map", false, "Unpins the map and exits")
	flag.StringVar(&ifname, "iface", "", "Network interface name (required for add mode)")
	flag.StringVar(&mac, "mac", "", "MAC address to add (required for add mode)")
	flag.UintVar(&tcHandle, "tc-handle", 0, "TC handle value (required for add mode)")
	flag.UintVar(&bandwidthMbps, "bandwidth", 0, "Bandwidth in Mbps (required for add mode)")
	flag.UintVar(&delayMs, "delay", 0, "Delay in ms (required for add mode)")

	flag.Parse()

	// Path to the map file of the eBPF program
	ebpfMapFile := "/sys/fs/bpf/MAC_HANDLE_BPS_DELAY"

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
		if ifname == "" || mac == "" || tcHandle == 0 || bandwidthMbps == 0 || delayMs == 0 {
			fmt.Println("错误: 添加模式需要提供以下参数: -iface, -mac, -tc-handle, -bandwidth, -delay")
			fmt.Println("用法示例: sudo go run main.go -mode add -iface eth0 -mac 00:11:22:33:44:55 -tc-handle 100 -bandwidth 10 -delay 50")
			os.Exit(1)
		}
		
		// 转换带宽从Mbps到Bps
		throttleRateBps := bandwidthMbps * 1000000
		
		if err := addMapEntry(ipHandleMap, ifname, mac, uint32(tcHandle), uint32(throttleRateBps), uint32(delayMs)); err != nil {
			fmt.Printf("错误: 添加表条目失败: %v\n", err)
			os.Exit(1)
		}
		
	default:
		fmt.Println("错误: 无效的操作模式。可用模式: view, clear, add")
		fmt.Println("用法示例:")
		fmt.Println("  查看表: sudo go run main.go -mode view")
		fmt.Println("  清空表: sudo go run main.go -mode clear")
		fmt.Println("  添加表: sudo go run main.go -mode add -iface eth0 -mac 00:11:22:33:44:55 -tc-handle 100 -bandwidth 10 -delay 50")
		os.Exit(1)
	}
}
