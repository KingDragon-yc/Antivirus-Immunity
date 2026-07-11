// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EVENT_PROCESS_EXEC 1
#define EVENT_PROCESS_EXIT 2
#define TASK_COMM_LEN 16
#define PATH_LEN 256

/*
 * Stable kernel/userspace wire ABI. Keep fields fixed-width and decode them
 * from bytes in Rust; never cast an arbitrary ring-buffer slice to this type.
 * The explicitly padded size is 328 bytes on all supported architectures.
 */
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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
    if (parent) {
        __u32 ppid = 0;
        BPF_CORE_READ_INTO(&ppid, parent, tgid);
        event->ppid = ppid;
    } else {
        event->ppid = 0;
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_header(event, EVENT_PROCESS_EXEC);
    bpf_probe_read_user_str(event->path, sizeof(event->path),
                            (const char *)ctx->args[0]);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Ignore individual thread exits; userspace models process lifetimes. */
    if ((__u32)pid_tgid != (__u32)(pid_tgid >> 32))
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    fill_header(event, EVENT_PROCESS_EXIT);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
