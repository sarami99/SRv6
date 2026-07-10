#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

struct srv6_policy_val {
    struct in6_addr usid_target;
    __u32 tenant_id;
    __u32 flex_algo;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct in6_addr);
    __type(value, struct srv6_policy_val);
} srv6_policy_map SEC(".maps");

struct mac_lookup_val {
    unsigned char mac_addr[ETH_ALEN];
    __u32 ifindex;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct in6_addr);
    __type(value, struct mac_lookup_val);
} next_hop_mac_map SEC(".maps");

static inline void ipv4_to_mapped_ipv6(__u32 ipv4, struct in6_addr *ipv6) {
    __builtin_memset(ipv6->s6_addr, 0, 10);
    ipv6->s6_addr[10] = 0xff;
    ipv6->s6_addr[11] = 0xff;
    // 💡 剛性事實：保持 Raw 內存拷貝，不作任何多餘的 bpf_htonl 翻轉！
    __builtin_memcpy(&ipv6->s6_addr[12], &ipv4, 4);
}

SEC("xdp")
int xdp_srv6_engine(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // =====================================================================
    // 🌍 模式 A: 邊緣 Ingress 封裝 (IPv4 -> SRv6)
    // =====================================================================
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;

        __u16 ip_tot_len = bpf_ntohs(ip->tot_len);
        struct in6_addr lookup_key = {};
        ipv4_to_mapped_ipv6(ip->daddr, &lookup_key);

        struct srv6_policy_val *policy = bpf_map_lookup_elem(&srv6_policy_map, &lookup_key);
        if (policy) {
            struct mac_lookup_val *mac_info = bpf_map_lookup_elem(&next_hop_mac_map, &policy->usid_target);
            if (mac_info) {
                unsigned char original_smac[ETH_ALEN];
                __builtin_memcpy(original_smac, eth->h_source, ETH_ALEN);

                if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct ipv6hdr))) return XDP_DROP;

                data = (void *)(long)ctx->data; data_end = (void *)(long)ctx->data_end;
                struct ethhdr *new_eth = data;
                if ((void *)(new_eth + 1) > data_end) return XDP_DROP;
                struct ipv6hdr *new_ipv6 = (void *)(new_eth + 1);
                if ((void *)(new_ipv6 + 1) > data_end) return XDP_DROP;

                __builtin_memcpy(new_eth->h_dest, mac_info->mac_addr, ETH_ALEN);
                __builtin_memcpy(new_eth->h_source, original_smac, ETH_ALEN);
                new_eth->h_proto = bpf_htons(ETH_P_IPV6);

                __builtin_memset(new_ipv6, 0, sizeof(struct ipv6hdr));
                new_ipv6->version = 6;
                new_ipv6->payload_len = bpf_htons(ip_tot_len);
                new_ipv6->nexthdr = 4; 
                new_ipv6->hop_limit = 64;
                
                new_ipv6->saddr.in6_u.u6_addr8[0] = 0xfc;
                new_ipv6->saddr.in6_u.u6_addr8[1] = 0x00;
                new_ipv6->saddr.in6_u.u6_addr8[15] = 0x02;

                new_ipv6->daddr = policy->usid_target;

                return bpf_redirect(mac_info->ifindex, 0);
            }
            // 🚨 SP級鋼鐵防禦：一旦策略命中但找不到二層下一跳，直接當場擊殺，絕不上浮給內核發ARP！
            return XDP_DROP; 
        }
    }

    // =====================================================================
    // 🌍 模式 B: 核心中轉與終點解封
    // =====================================================================
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end) return XDP_PASS;

        if (ipv6->nexthdr == 58) return XDP_PASS; 
        if (ipv6->daddr.in6_u.u6_addr16[0] != bpf_htons(0xfc00)) return XDP_PASS;

        // 1. 🏛️ 終點解封裝 (End.DT4) 判定
        struct srv6_policy_val *decap_policy = bpf_map_lookup_elem(&srv6_policy_map, &ipv6->daddr);
        if (decap_policy) {
            // 🎯 只要 tenant_id 匹配或者前綴符合本機 End.DT4 宣告，直接強行剝離！
            __builtin_memmove((void *)eth + sizeof(struct ipv6hdr), eth, sizeof(struct ethhdr));
            if (bpf_xdp_adjust_head(ctx, sizeof(struct ipv6hdr))) return XDP_DROP;

            data = (void *)(long)ctx->data; data_end = (void *)(long)ctx->data_end;
            struct ethhdr *new_eth = data;
            if ((void *)(new_eth + 1) > data_end) return XDP_DROP;

            new_eth->h_proto = bpf_htons(ETH_P_IP);
            return XDP_PASS; 
        }

        // 2. 🏎️ 5-18 號順向移位前推引擎
        if (ipv6->daddr.in6_u.u6_addr16[3] != 0) {
            #pragma unroll
            for (int i = 2; i < 7; i++) {
                ipv6->daddr.in6_u.u6_addr16[i] = ipv6->daddr.in6_u.u6_addr16[i+1];
            }
            ipv6->daddr.in6_u.u6_addr16[7] = 0;

            struct in6_addr network_order_key;
            #pragma unroll
            for (int j = 0; j < 4; j++) {
                network_order_key.in6_u.u6_addr32[j] = ipv6->daddr.in6_u.u6_addr32[j];
            }

            data = (void *)(long)ctx->data; data_end = (void *)(long)ctx->data_end;
            struct ethhdr *redirect_eth = data;
            if ((void *)(redirect_eth + 1) > data_end) return XDP_DROP;

            struct mac_lookup_val *mac_info = bpf_map_lookup_elem(&next_hop_mac_map, &network_order_key);
            if (mac_info) {
                __builtin_memcpy(redirect_eth->h_dest, mac_info->mac_addr, ETH_ALEN);
                return bpf_redirect(mac_info->ifindex, 0);
            }
            return XDP_DROP; 
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
