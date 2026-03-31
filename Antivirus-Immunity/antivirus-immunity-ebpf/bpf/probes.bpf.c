// SPDX-License-Identifier: GPL-2.0
//
// Antivirus-Immunity eBPF Kernel Probes
// ======================================
//
// CO-RE (Compile Once, Run Everywhere) eBPF probes for Linux kernel 5.4+.
//
// Build:
//   clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
//       -I /usr/include/bpf \
//       -c probes.bpf.c -o probes.bpf.o
//
// Then generate skeleton:
//   bpftool gen skeleton probes.bpf.o > probes.skel.h
//
// Or use libbpf-cargo to automate this in build.rs.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ============================================================
// Shared Data Structures (mirrored in Rust userspace)
// ============================================================

#define MAX_COMM_LEN     64
#define MAX_PATH_LEN     256
#define MAX_ARGS_LEN     512

// Event types (must match Rust ProbeType enum)
enum event_type {
    EVENT_PROCESS_EXEC   = 1,
    EVENT_PROCESS_EXIT   = 2,
    EVENT_TCP_CONNECT    = 3,
    EVENT_UDP_SEND       = 4,
    EVENT_FILE_OPEN      = 5,
    EVENT_INODE_CREATE   = 6,
    EVENT_CRED_CHANGE    = 7,
};

// Generic event header
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u32 ns_pid;
    __u8  event_type;
    char  comm[MAX_COMM_LEN];
};

// Process exec event
struct exec_event {
    struct event hdr;
    char  filename[MAX_PATH_LEN];
    char  args[MAX_ARGS_LEN];
};

// Network event
struct net_event {
    struct event hdr;
    __u32 src_addr;    // IPv4 (network byte order)
    __u32 dst_addr;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;    // IPPROTO_TCP / IPPROTO_UDP
};

// File access event
struct file_event {
    struct event hdr;
    char  path[MAX_PATH_LEN];
    __u32 flags;       // O_RDONLY, O_WRONLY, etc.
};

// Credential change event
struct cred_event {
    struct event hdr;
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_euid;
    __u32 new_euid;
};

// ============================================================
// BPF Ring Buffer — kernel → userspace event channel
// ============================================================

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB ring buffer
} events SEC(".maps");

// ============================================================
// Helper: fill common event header
// ============================================================

static __always_inline void fill_event_header(struct event *e, __u8 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = pid_tgid >> 32;
    e->ns_pid       = pid_tgid >> 32;  // TODO: resolve namespace PID
    e->uid          = uid_gid;
    e->gid          = uid_gid >> 32;
    e->cgroup_id    = bpf_get_current_cgroup_id();
    e->event_type   = type;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // Get ppid from current task
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    BPF_CORE_READ_INTO(&e->ppid, parent, tgid);
}

// ============================================================
// PROBE 1: Process Execution (tracepoint/syscalls/sys_enter_execve)
// ============================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_event_header(&e->hdr, EVENT_PROCESS_EXEC);

    // Read filename from first argument
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    // Read first argument
    const char **argv = (const char **)ctx->args[1];
    const char *arg0;
    bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
    if (arg0)
        bpf_probe_read_user_str(e->args, sizeof(e->args), arg0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// PROBE 2: TCP Connect (kprobe/tcp_connect)
// ============================================================

SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct net_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_event_header(&e->hdr, EVENT_TCP_CONNECT);

    BPF_CORE_READ_INTO(&e->src_addr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->dst_addr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&e->dst_port, sk, __sk_common.skc_dport);
    BPF_CORE_READ_INTO(&e->src_port, sk, __sk_common.skc_num);
    e->protocol = IPPROTO_TCP;

    // Convert dst_port from network byte order
    e->dst_port = __builtin_bswap16(e->dst_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// PROBE 3: Credential Change (kprobe/commit_creds)
//   — Detect privilege escalation (uid → 0)
// ============================================================

SEC("kprobe/commit_creds")
int handle_cred_change(struct pt_regs *ctx)
{
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);
    struct cred_event *e;

    __u32 new_uid;
    BPF_CORE_READ_INTO(&new_uid, new_cred, uid.val);

    // Only report when escalating to root
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 old_uid = uid_gid & 0xFFFFFFFF;
    if (new_uid == old_uid) return 0;  // No change

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_event_header(&e->hdr, EVENT_CRED_CHANGE);
    e->old_uid  = old_uid;
    e->new_uid  = new_uid;
    BPF_CORE_READ_INTO(&e->new_euid, new_cred, euid.val);

    // Read old euid from current
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old_cred;
    BPF_CORE_READ_INTO(&old_cred, task, real_cred);
    BPF_CORE_READ_INTO(&e->old_euid, old_cred, euid.val);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================
// PROBE 4: File Open (LSM/security_file_open)
//   — Monitor sensitive file access
//   — NOTE: LSM hooks require CONFIG_BPF_LSM=y in kernel
// ============================================================

SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file, int ret)
{
    if (ret != 0) return ret;  // Already denied by other LSM

    struct file_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_event_header(&e->hdr, EVENT_FILE_OPEN);

    // Read file path from dentry
    struct path f_path;
    BPF_CORE_READ_INTO(&f_path, file, f_path);
    struct dentry *dentry = f_path.dentry;
    BPF_CORE_READ_STR(e->path, dentry, d_name.name);

    e->flags = BPF_CORE_READ(file, f_flags);

    bpf_ringbuf_submit(e, 0);
    return 0;  // Allow — userspace decides action
}

// ============================================================
// PROBE 5: Inode Create (LSM/security_inode_create)
//   — Detect new file creation in sensitive dirs
// ============================================================

SEC("lsm/inode_create")
int BPF_PROG(handle_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    if (ret != 0) return ret;

    struct file_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_event_header(&e->hdr, EVENT_INODE_CREATE);

    BPF_CORE_READ_STR(e->path, dentry, d_name.name);
    e->flags = mode;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
