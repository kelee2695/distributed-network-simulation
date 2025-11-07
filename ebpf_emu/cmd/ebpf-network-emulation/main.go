package main

import (
	"flag"
	"log"

	"netsimlation/distribute/ebpf/internal/utils"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go edt ebpf/network_simulation.c -- -I../headers

const (
	PIN_PATH = "/sys/fs/bpf/"
)

var (
	iface_name *string
	clear_flag *bool
)

func init() {
	iface_name = flag.String("iface", "", "目标网卡接口名称，用于挂载或清理eBPF程序")
	clear_flag = flag.Bool("clear", false, "清理指定网卡接口上的eBPF程序和TC组件")
}

func main() {
	flag.Parse()

	// 检查是否指定了网卡接口
	if *iface_name == "" {
		log.Fatalf("错误: 必须使用 -iface 参数指定目标网卡接口名称")
	}

	// 获取网络接口
	iface, err := utils.GetIface(*iface_name)
	if err != nil {
		log.Fatalf("错误: 找不到指定的网卡接口 %s: %v\n请使用 -iface 参数指定正确的网卡名称", *iface_name, err)
	}

	// 检查是否只需要清理
	if *clear_flag {
		log.Printf("正在清理 %s 接口上的 eBPF 程序和 TC 组件...", *iface_name)
		if err := utils.ClearEbpf(iface); err != nil {
			log.Fatalf("清理失败: %v", err)
		}
		log.Printf("清理完成")
		return
	}

	// 正常加载 eBPF 程序
	objs := edtObjects{}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: PIN_PATH,
		},
	}

	if err := loadEdtObjects(&objs, &opts); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	progFd := objs.edtPrograms.TcMain.FD()

	// Create clsact qdisc
	if _, err := utils.CreateClsactQdisc(iface); err != nil {
		log.Fatalf("cannot create clsact qdisc: %v", err)
	}

	// Create fq qdisc
	if _, err := utils.CreateFQdisc(iface); err != nil {
		log.Fatalf("cannot create fq qdisc: %v", err)
	}

	// 固定使用egress方向
	handle := uint32(netlink.HANDLE_MIN_EGRESS)
	log.Printf("Attaching eBPF program to the egress direction of %s...", *iface_name)
	
	// Attach bpf program
	if _, err := utils.CreateTCBpfFilter(iface, progFd, handle, "edt_bandwidth"); err != nil {
		log.Fatalf("cannot create bpf filter: %v", err)
	}

	// Update jump map with delay prog
	err = objs.Progs.Update(uint32(0), uint32(objs.SetDelay.FD()), ebpf.UpdateAny)
	if err != nil {
		println("Update", err.Error())
	}
}
