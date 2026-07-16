// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EVENT_NETWORK_BLOCKED 3
#define EVENT_FILE_BLOCKED 4
#define TASK_COMM_LEN 16
#define PATH_LEN 256

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60
#define XDP_DROP 1
#define XDP_PASS 2
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_TRUNC 00001000
#define O_APPEND 00002000

#define FILE_OP_OPEN (1U << 0)
#define FILE_OP_WRITE (1U << 1)

#define STAT_EVENTS_EMITTED 0
#define STAT_RINGBUF_DROPPED 1
#define STAT_XDP_BLOCKED 2
#define STAT_TC_BLOCKED 3
#define STAT_LSM_BLOCKED 4
#define STAT_MAX 5

struct event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 ns_pid;
    __u32 event_type;
    __u32 arg0;
    __u32 arg1;
    __u16 port;
    __u16 reserved;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
    __u32 tail_padding;
};

struct policy_config {
    __u32 enforce;
    __u32 fail_closed;
    __u64 generation;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct path_lpm_key {
    __u32 prefixlen;
    __u8 path[PATH_LEN];
};

struct path_rule {
    __u32 rule_id;
    __u32 deny_mask;
    __u16 path_len;
    __u8 recursive;
    __u8 reserved;
};

struct path_scratch {
    struct path_lpm_key key;
    char path_buf[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} guard_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_config);
} policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
} ipv4_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
} ipv6_blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} blocked_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 256);
    __type(key, struct path_lpm_key);
    __type(value, struct path_rule);
} protected_paths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} guard_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} network_event_clock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} scratch SEC(".maps");

static __always_inline void increment_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&guard_stats, &index);
    if (value)
        *value += 1;
}

static __always_inline bool should_emit_network_event(void)
{
    __u32 zero = 0;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&network_event_clock, &zero);
    if (!last)
        return false;
    if (*last && now - *last < 1000000000ULL)
        return false;
    *last = now;
    return true;
}

static __always_inline bool enforcing(void)
{
    __u32 zero = 0;
    struct policy_config *config = bpf_map_lookup_elem(&policy, &zero);
    return config && config->enforce;
}

static __always_inline void fill_header(struct event *event, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid_tgid >> 32;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->ns_pid = event->pid;
    event->event_type = event_type;
    event->arg0 = 0;
    event->arg1 = 0;
    event->port = 0;
    event->reserved = 0;
    event->tail_padding = 0;
    event->path[0] = '\0';
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    event->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
}

static __always_inline void emit_network_event(__u32 src, __u32 dst, __u16 port,
                                                __u16 direction, bool enforce)
{
    struct event *event = bpf_ringbuf_reserve(&guard_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_RINGBUF_DROPPED);
        return;
    }
    /* XDP/TC programs have no process context and cannot call current-task
     * helpers on all supported kernels. Initialize an explicit pid-less event
     * instead of making the entire guard object unverifiable. */
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_NETWORK_BLOCKED;
    event->arg0 = src;
    event->arg1 = dst;
    event->port = port;
    event->reserved = direction;
    event->tail_padding = enforce;
    bpf_ringbuf_submit(event, 0);
    increment_stat(STAT_EVENTS_EMITTED);
}

static __always_inline void emit_network_event_v6(const __u8 *src, const __u8 *dst,
                                                   __u16 port, __u16 direction,
                                                   bool enforce)
{
    struct event *event = bpf_ringbuf_reserve(&guard_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_RINGBUF_DROPPED);
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_NETWORK_BLOCKED;
    event->port = port;
    event->reserved = direction | 0x100;
    event->tail_padding = enforce;
    __builtin_memcpy(event->path, src, 16);
    __builtin_memcpy(event->path + 16, dst, 16);
    bpf_ringbuf_submit(event, 0);
    increment_stat(STAT_EVENTS_EMITTED);
}

static __always_inline int inspect_packet(void *data, void *data_end, bool ingress)
{
    __u8 *cursor = data;
    if (cursor + 14 > (__u8 *)data_end)
        return 0;

    __u16 protocol = bpf_ntohs(*(__be16 *)(cursor + 12));
    __u32 offset = 14;
    #pragma clang loop unroll(full)
    for (int vlan = 0; vlan < 2; vlan++) {
        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
            break;
        if (cursor + offset + 4 > (__u8 *)data_end)
            return 0;
        protocol = bpf_ntohs(*(__be16 *)(cursor + offset + 2));
        offset += 4;
    }

    if (protocol == ETH_P_IP) {
        if (cursor + offset + 20 > (__u8 *)data_end)
            return 0;
        __u8 version_ihl = *(cursor + offset);
        __u32 ihl = (version_ihl & 0x0f) * 4;
        if ((version_ihl >> 4) != 4 || ihl < 20 || cursor + offset + ihl > (__u8 *)data_end)
            return 0;

        __u8 ip_protocol = *(cursor + offset + 9);
        __u32 src = *(__u32 *)(cursor + offset + 12);
        __u32 dst = *(__u32 *)(cursor + offset + 16);
        __u32 candidate = ingress ? src : dst;
        struct ipv4_lpm_key key = {.prefixlen = 32};
        __builtin_memcpy(key.addr, &candidate, sizeof(key.addr));

        __u16 port = 0;
        __u16 fragment = bpf_ntohs(*(__be16 *)(cursor + offset + 6));
        if ((ip_protocol == IPPROTO_TCP || ip_protocol == IPPROTO_UDP) &&
            (fragment & 0x1fff) == 0 &&
            cursor + offset + ihl + 4 <= (__u8 *)data_end) {
            __u16 dst_port = bpf_ntohs(*(__be16 *)(cursor + offset + ihl + 2));
            port = dst_port;
        }

        bool matched = bpf_map_lookup_elem(&ipv4_blacklist, &key) ||
                       bpf_map_lookup_elem(&blocked_ports, &port);
        if (matched) {
            bool enforce = enforcing();
            if (should_emit_network_event())
                emit_network_event(src, dst, port, ingress ? 1 : 2, enforce);
            return enforce;
        }
    } else if (protocol == ETH_P_IPV6) {
        if (cursor + offset + 40 > (__u8 *)data_end)
            return 0;
        const __u8 *src = cursor + offset + 8;
        const __u8 *dst = cursor + offset + 24;
        struct ipv6_lpm_key key = {.prefixlen = 128};
        __builtin_memcpy(key.addr, ingress ? src : dst, 16);
        __u16 port = 0;
        __u8 next_header = *(cursor + offset + 6);
        __u8 *transport = cursor + offset + 40;
        #pragma clang loop unroll(full)
        for (int extension = 0; extension < 4; extension++) {
            if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
                if (transport + 4 <= (__u8 *)data_end)
                    port = bpf_ntohs(*(__be16 *)(transport + 2));
                break;
            }
            if (next_header == IPPROTO_FRAGMENT) {
                if (transport + 8 > (__u8 *)data_end)
                    break;
                __u16 fragment = bpf_ntohs(*(__be16 *)(transport + 2));
                next_header = *transport;
                transport += 8;
                if (fragment & 0xfff8)
                    break;
                continue;
            }
            if (next_header != IPPROTO_HOPOPTS && next_header != IPPROTO_ROUTING &&
                next_header != IPPROTO_DSTOPTS && next_header != IPPROTO_AH)
                break;
            if (transport + 2 > (__u8 *)data_end)
                break;
            __u8 following_header = transport[0];
            __u32 extension_length = next_header == IPPROTO_AH
                                         ? ((transport[1] + 2) * 4)
                                         : ((transport[1] + 1) * 8);
            if (extension_length < 8 ||
                transport + extension_length > (__u8 *)data_end)
                break;
            next_header = following_header;
            transport += extension_length;
        }

        bool matched = bpf_map_lookup_elem(&ipv6_blacklist, &key) ||
                       bpf_map_lookup_elem(&blocked_ports, &port);
        if (matched) {
            bool enforce = enforcing();
            if (should_emit_network_event())
                emit_network_event_v6(src, dst, port, ingress ? 1 : 2, enforce);
            return enforce;
        }
    }
    return 0;
}

SEC("xdp")
int xdp_ingress_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (inspect_packet(data, data_end, true)) {
        increment_stat(STAT_XDP_BLOCKED);
        return XDP_DROP;
    }
    return XDP_PASS;
}

SEC("tc")
int tc_egress_guard(struct __sk_buff *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (inspect_packet(data, data_end, false)) {
        increment_stat(STAT_TC_BLOCKED);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

static __always_inline int guard_file(struct file *file, __u32 requested_op)
{
    __u32 zero = 0;
    struct path_scratch *tmp = bpf_map_lookup_elem(&scratch, &zero);
    if (!tmp)
        return 0;

    long length = bpf_d_path(&file->f_path, tmp->path_buf, sizeof(tmp->path_buf));
    if (length <= 1 || length > PATH_LEN)
        return 0;

    char *path_start = tmp->path_buf + PATH_LEN - length;
    __builtin_memset(&tmp->key, 0, sizeof(tmp->key));
    tmp->key.prefixlen = PATH_LEN * 8;
    if (bpf_probe_read_kernel_str(tmp->key.path, sizeof(tmp->key.path), path_start) < 0)
        return 0;

    struct path_rule *rule = bpf_map_lookup_elem(&protected_paths, &tmp->key);
    if (!rule || !(rule->deny_mask & requested_op))
        return 0;

    __u32 path_len = (__u32)length - 1;
    if (rule->path_len == 0 || rule->path_len >= PATH_LEN)
        return 0;
    if ((!rule->recursive && path_len != rule->path_len) ||
        (rule->recursive && path_len > rule->path_len &&
         tmp->key.path[rule->path_len] != '/'))
        return 0;

    bool enforce = enforcing();

    struct event *event = bpf_ringbuf_reserve(&guard_events, sizeof(*event), 0);
    if (event) {
        fill_header(event, EVENT_FILE_BLOCKED);
        event->arg0 = requested_op;
        event->tail_padding = enforce;
        bpf_probe_read_kernel_str(event->path, sizeof(event->path), path_start);
        bpf_ringbuf_submit(event, 0);
        increment_stat(STAT_EVENTS_EMITTED);
    } else {
        increment_stat(STAT_RINGBUF_DROPPED);
    }
    if (enforce) {
        increment_stat(STAT_LSM_BLOCKED);
        return -1;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open_guard, struct file *file, int ret)
{
    if (ret)
        return ret;
    unsigned int flags = BPF_CORE_READ(file, f_flags);
    __u32 op = FILE_OP_OPEN;
    if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR ||
        (flags & (O_TRUNC | O_APPEND)))
        op |= FILE_OP_WRITE;
    return guard_file(file, op);
}

char LICENSE[] SEC("license") = "GPL";
