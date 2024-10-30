// sched-metrics.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Define key for the histogram map
struct hist_key_t {
    u32 pid;
    u32 bucket;
};

// Map to store wakeup timestamp per PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);    // PID
    __type(value, u64);  // Timestamp in ns
} pid_start_time SEC(".maps");

// Map to store histogram of waiting times
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 102400);
    __type(key, struct hist_key_t);    // PID and Bucket index
    __type(value, u64);                // Count
} wait_time_hist SEC(".maps");

// Custom log2 function for histogram bucket calculation
static __always_inline u32 log2(u64 v) {
    u32 r = 0;
    if (v == 0)
        return 0;
    if (v >> 32) { v >>= 32; r += 32; }
    if (v >> 16) { v >>= 16; r += 16; }
    if (v >> 8)  { v >>= 8;  r += 8; }
    if (v >> 4)  { v >>= 4;  r += 4; }
    if (v >> 2)  { v >>= 2;  r += 2; }
    if (v >> 1)  {           r += 1; }
    return r;
}

// Define structures matching the tracepoint formats

struct sched_wakeup_args {
    u64 __unused__;
    char comm[16];
    pid_t pid;
    int prio;
    int success;
    int target_cpu;
};

struct sched_switch_args {
    u64 __unused__;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};

// Tracepoint for sched_wakeup
SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx) {
    u32 pid = ctx->pid;
    u64 ts = bpf_ktime_get_ns();

    // Store wakeup timestamp
    bpf_map_update_elem(&pid_start_time, &pid, &ts, BPF_ANY);

    return 0;
}

// Tracepoint for sched_switch
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx) {
    u32 pid = ctx->next_pid;
    u64 *tsp = NULL;
    u64 delta = 0;

    // Get current timestamp
    u64 ts = bpf_ktime_get_ns();

    // Lookup wakeup timestamp
    tsp = bpf_map_lookup_elem(&pid_start_time, &pid);
    if (tsp) {
        delta = ts - *tsp;

        // Filter out wait times less than 20 milliseconds (20,000,000 ns)
        if (delta < 40000000) {
            // Remove timestamp entry
            bpf_map_delete_elem(&pid_start_time, &pid);
            return 0;
        }

        // Calculate histogram bucket index
        u32 index = log2(delta);
        if (index >= 64)
            index = 63;

        // Create histogram key
        struct hist_key_t hist_key = {};
        hist_key.pid = pid;
        hist_key.bucket = index;

        // Update histogram
        u64 *count = bpf_map_lookup_elem(&wait_time_hist, &hist_key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            u64 init_count = 1;
            bpf_map_update_elem(&wait_time_hist, &hist_key, &init_count, BPF_ANY);
        }

        // Remove timestamp entry
        bpf_map_delete_elem(&pid_start_time, &pid);
    }

    return 0;
}
