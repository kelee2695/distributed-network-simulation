#include <linux/if_ether.h> // 引入ETH_ALEN定义

// 复合键结构体：包含网卡index和源MAC地址
struct flow_key {
    unsigned int ifindex;        // 网卡接口索引
    unsigned char src_mac[ETH_ALEN];  // 源MAC地址
} __attribute__((packed)); // 确保结构体按照实际大小对齐

struct handle_bps_delay {
    __u32 tc_handle;
    __u32 throttle_rate_bps;
    __u32 delay_ms;
} HANDLE_BPS_DELAY;

// 修改映射键类型为复合键（网卡index + MAC地址）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);    // 使用复合键
    __type(value, HANDLE_BPS_DELAY);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pin map by name (accessible under /sys/fs/bpf/<name>)
    __uint(max_entries, 65535);
} MAC_HANDLE_BPS_DELAY SEC(".maps");

// 为了兼容，保留IP_HANDLE_BPS_DELAY的引用，但实际使用MAC_HANDLE_BPS_DELAY
#define IP_HANDLE_BPS_DELAY MAC_HANDLE_BPS_DELAY