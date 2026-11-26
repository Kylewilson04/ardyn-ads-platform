// crates/ads-ebpf/src/sentinel_lsm.c
// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define MAY_WRITE 0x00000002
#define TMPFS_MAGIC 0x01021994
#define SOCKFS_MAGIC 0x534F434B

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   // Protected PID
    __type(value, __u64); // Blocked Write Counter
} ardyn_protected_pids SEC(".maps");

SEC("lsm/file_permission")
int BPF_PROG(ardyn_block_nonvolatile_writes, void *file, int mask) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *blocked_cnt = bpf_map_lookup_elem(&ardyn_protected_pids, &pid);
    if (!blocked_cnt) return 0;

    if (mask & MAY_WRITE) {
        __sync_fetch_and_add(blocked_cnt, 1);
        bpf_printk("ARDYN_LSM: Blocked non-volatile write from sovereign PID %u\n", pid);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(ardyn_block_ptrace_snooping, void *child, unsigned int mode) {
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&ardyn_protected_pids, &caller_pid)) {
        return -EACCES;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
