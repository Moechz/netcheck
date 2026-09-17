// NetCheck eBPF traffic counters.
//
// The program is attached to one AF_PACKET socket. It updates per-interface
// counters in kernel BPF memory and returns 0, which discards the packet copy
// before Go has to read it.
#include "../_headers/common.h"

struct __sk_buff_min {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
};

struct traffic_value {
    __u64 rx_bytes;
    __u64 rx_packets;
    __u64 tx_bytes;
    __u64 tx_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);
    __type(value, struct traffic_value);
} traffic SEC(".maps");

SEC("socket")
int count_packet(struct __sk_buff_min *skb)
{
    struct traffic_value *value;
    __u32 key;
    __u32 direction;

    if (!skb || !skb->len)
        return 0;
    key = skb->ifindex;
    if (!key)
        return 0;

    value = bpf_map_lookup_elem(&traffic, &key);
    if (!value) {
        struct traffic_value zero = {};
        bpf_map_update_elem(&traffic, &key, &zero, BPF_ANY);
        value = bpf_map_lookup_elem(&traffic, &key);
        if (!value)
            return 0;
    }

    /* PACKET_OUTGOING means transmitted by this host. */
    direction = skb->pkt_type == 4;
    if (direction) {
        value->tx_bytes += skb->len;
        value->tx_packets++;
    } else {
        value->rx_bytes += skb->len;
        value->rx_packets++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
