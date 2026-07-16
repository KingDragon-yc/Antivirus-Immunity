/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __IMMUNITY_MINIMAL_VMLINUX_H__
#define __IMMUNITY_MINIMAL_VMLINUX_H__

/*
 * Minimal CO-RE type declarations. Only fields read by probes.bpf.c are
 * declared. preserve_access_index makes clang emit BTF relocations which
 * libbpf resolves against /sys/kernel/btf/vmlinux at load time.
 */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef _Bool bool;
#ifndef true
#define true 1
#define false 0
#endif

#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_F_NO_PREALLOC 1

struct task_struct {
    int tgid;
    struct task_struct *real_parent;
} __attribute__((preserve_access_index));

struct vfsmount;
struct dentry;

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    struct path f_path;
    unsigned int f_flags;
} __attribute__((preserve_access_index));

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct __sk_buff {
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
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

/* Layout of tracepoint/syscalls/sys_enter_* up through args[]. */
struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
} __attribute__((preserve_access_index));

/* Layout of tracepoint/sched/sched_process_exec up through old_pid. */
struct trace_event_raw_sched_process_exec {
    __u64 unused;
    __u32 __data_loc_filename;
    __s32 pid;
    __s32 old_pid;
    char __data[0];
} __attribute__((preserve_access_index));

#endif
