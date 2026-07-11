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

#define BPF_MAP_TYPE_RINGBUF 27

struct task_struct {
    int tgid;
    struct task_struct *real_parent;
} __attribute__((preserve_access_index));

/* Layout of tracepoint/syscalls/sys_enter_* up through args[]. */
struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
} __attribute__((preserve_access_index));

#endif
