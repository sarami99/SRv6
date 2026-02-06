#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- MAP DEFINITIONS ---

// 1. Routing Table (LPM Trie)
// Key: IP Prefix (Network Order), Value: Action Rule
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 200000); // Support 200k rules
    __uint(map_flags, BPF_F_NO_PREALLOC); 
    __type(key, struct bpf_lpm_trie_key);
    __type(value, struct rule_value);
} routing_table SEC(".maps");

// 2. Telemetry Map (Per-CPU Array for speed)
// We don't want atomic locks slowing us down, so each CPU counts its own drops.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats_value);
} global_stats SEC(".maps");

// --- STRUCTS ---

struct bpf_lpm_trie_key {
    __u32 prefixlen;
    __u32 data; // IPv4 Address
};

struct rule_value {
    __u32 action;       // 0=PASS, 1=DROP, 2=REDIRECT
    __u32 ifindex;      // Interface to redirect to (if REDIRECT)
};

struct stats_value {
    __u64 dropped;
    __u64 redirected;
};

// --- LOGIC ---

SEC("xdp_soldier")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parsing (Fast fail)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    // Only handle IPv4 for this example
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 2. Lookup in LPM Map
    struct bpf_lpm_trie_key key;
    key.prefixlen = 32; // Default to looking for exact match first
    key.data = ip->saddr; // Filtering based on Source IP (The Attacker)

    struct rule_value *rule = bpf_map_lookup_elem(&routing_table, &key);

    // 3. Default Policy: Allow if no rule found
    if (!rule) return XDP_PASS;

    // 4. Update Stats (Index 0)
    __u32 zero = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&global_stats, &zero);

    // 5. Execute Action
    switch (rule->action) {
        case 1: // DROP
            if (stats) stats->dropped++; 
            return XDP_DROP;
        
        case 2: // REDIRECT
            if (stats) stats->redirected++;
            return bpf_redirect(rule->ifindex, 0);

        default:
            return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
