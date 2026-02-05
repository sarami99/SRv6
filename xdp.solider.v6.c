#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h> // You need this struct!
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp_srv6_firewall")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // --- CORRECTION: Check for IPv6 (0x86DD) ---
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;

        // 1. FIREWALL THE OUTER LAYER (The Transport)
        // Example: Only allow traffic from known SRv6 Locators (e.g. FD00::/8)
        // If (ip6->saddr doesn't match Prefix) -> DROP

        // 2. DECAPSULATION LOGIC (Peel the Onion)
        // We need to find the Inner Packet.
        // In SRv6 L3VPN, the Next Header is often IPPROTO_IPIP (4) for IPv4-in-IPv6
        
        if (ip6->nexthdr == IPPROTO_IPIP) { // 4
            // Jump to Inner IPv4 Header
            struct iphdr *inner_ip = (void *)(ip6 + 1);
            if ((void *)(inner_ip + 1) > data_end) return XDP_PASS;

            // 3. FIREWALL THE INNER LAYER (The Application)
            // Now we check TCP/UDP on the *original* packet
            if (inner_ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)(inner_ip + 1);
                if ((void *)(tcp + 1) > data_end) return XDP_PASS;

                // --- YOUR LOGIC HERE ---
                // "If SYN and Inner_Src != Whitelist -> DROP"
                if (tcp->syn) {
                    // Lookup inner_ip->saddr in map...
                    // return XDP_DROP;
                }
            }
        }
    } 
    // Handle Legacy IPv4 (if any exists on Mgt interface)
    else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        // ... Old logic for native IPv4 ...
    }

    return XDP_PASS;
}
