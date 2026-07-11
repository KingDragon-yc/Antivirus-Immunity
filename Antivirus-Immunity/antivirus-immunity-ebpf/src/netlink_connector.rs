//! Netlink Connector — 内核进程事件零轮询监听
//!
//! 利用 Linux 内核自带的 NETLINK_CONNECTOR 机制，通过 CN_IDX_PROC
//! 订阅进程 FORK / EXEC / EXIT 事件。内核在事件发生时主动推送消息到
//! 用户态 socket，彻底消除 /proc 轮询的 TOCTOU 竞态和 CPU 浪费。
//!
//! 协议栈:
//!   nlmsghdr (16B) → cn_msg (20B) → proc_event (可变)
//!
//! 参考: include/uapi/linux/cn_proc.h, include/uapi/linux/netlink.h

#![cfg(target_os = "linux")]

use crate::probe::{ProbeType, RawProbeEvent};
use anyhow::Result;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// ─── Netlink constants ───
const NETLINK_CONNECTOR: i32 = 11;
const NLMSG_NOOP: u16 = 0x1;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const NLMSG_OVERHEAD: usize = 16;
const NLMSG_ALIGNTO: usize = 4;

// ─── Connector constants ───
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const CN_IDX_SIZE: usize = 16;

// ─── Process event types (what field) ───
const PROC_EVENT_NONE: u32 = 0x0000_0000;
const PROC_EVENT_FORK: u32 = 0x0000_0001;
const PROC_EVENT_EXEC: u32 = 0x0000_0002;
const PROC_EVENT_UID: u32 = 0x0000_0004;
const PROC_EVENT_GID: u32 = 0x0000_0040;
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

// ─── C structure definitions (repr(C), packed-compatible) ───

/// struct nlmsghdr — Netlink message header
#[repr(C)]
#[derive(Debug)]
struct NlMsgHdr {
    nlmsg_len: u32,   // Length of message including header
    nlmsg_type: u16,  // Message type (NLMSG_DONE for connector)
    nlmsg_flags: u16, // Flags (NLM_F_MULTI)
    nlmsg_seq: u32,   // Sequence number
    nlmsg_pid: u32,   // Sending port ID
}

/// struct cb_id — Connector bus ID
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CbId {
    idx: u32,
    val: u32,
}

const _CB_ID_BYTES: usize = CN_IDX_SIZE;

/// struct cn_msg — Connector message header
#[repr(C)]
#[derive(Debug)]
struct CnMsg {
    id: CbId,
    seq: u32,
    ack: u32,
    len: u16, // Length of payload data
    flags: u16,
}

/// After the proc_event header, the event-specific union payload starts.
const PROC_EVENT_HDR_SIZE: usize = 16;

/// struct sockaddr_nl — Netlink socket address
#[repr(C)]
struct SockAddrNl {
    nl_family: libc::sa_family_t, // AF_NETLINK = 16
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

/// Netlink Connector listener — wraps an AF_NETLINK socket subscribed to CN_IDX_PROC
pub struct NetlinkConnector {
    fd: OwnedFd,
}

impl NetlinkConnector {
    /// Create and bind a NETLINK_CONNECTOR socket, subscribe to process events.
    pub fn new() -> Result<Self> {
        let sock = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NETLINK_CONNECTOR,
            )
        };
        if sock < 0 {
            return Err(anyhow::anyhow!(
                "socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR) failed: {}",
                io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(sock) };

        // Bind to any port, subscribe to CN_IDX_PROC group
        let addr = SockAddrNl {
            nl_family: libc::AF_NETLINK as libc::sa_family_t,
            nl_pad: 0,
            nl_pid: 0,    // Kernel assigns a port
            nl_groups: 1, // CN_IDX_PROC multicast group
        };

        let bind_ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const SockAddrNl as *const libc::sockaddr,
                std::mem::size_of::<SockAddrNl>() as u32,
            )
        };
        if bind_ret < 0 {
            return Err(anyhow::anyhow!(
                "bind(NETLINK_CONNECTOR) failed: {}",
                io::Error::last_os_error()
            ));
        }

        // Send PROC_CN_MCAST_LISTEN to enable event delivery
        Self::send_listen_cmd(fd.as_raw_fd(), true)?;

        // Set receive timeout to 100ms so we can yield to the async runtime
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000, // 100ms
        };
        let timeout_ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            )
        };
        if timeout_ret < 0 {
            return Err(anyhow::anyhow!(
                "setsockopt(SO_RCVTIMEO) failed: {}",
                io::Error::last_os_error()
            ));
        }

        Ok(Self { fd })
    }

    /// Send a PROC_CN_MCAST_LISTEN message to start/stop receiving events.
    fn send_listen_cmd(sock_fd: RawFd, enable: bool) -> Result<()> {
        // Build: nlmsghdr + cn_msg + u32 (listen state)
        let payload: u32 = if enable { 1 } else { 0 };
        let cn_msg_len = std::mem::size_of::<CnMsg>() + std::mem::size_of::<u32>();
        let total_len = NLMSG_OVERHEAD + cn_msg_len;

        let mut buf = vec![0u8; total_len];

        // nlmsghdr
        let hdr = NlMsgHdr {
            nlmsg_len: total_len as u32,
            nlmsg_type: NLMSG_DONE,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: std::process::id(), // our PID
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &hdr as *const NlMsgHdr as *const u8,
                buf.as_mut_ptr(),
                NLMSG_OVERHEAD,
            );
        }

        // cn_msg
        let cn = CnMsg {
            id: CbId {
                idx: CN_IDX_PROC,
                val: CN_VAL_PROC,
            },
            seq: 0,
            ack: 0,
            len: std::mem::size_of::<u32>() as u16,
            flags: 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &cn as *const CnMsg as *const u8,
                buf.as_mut_ptr().add(NLMSG_OVERHEAD),
                std::mem::size_of::<CnMsg>(),
            );
            std::ptr::copy_nonoverlapping(
                &payload as *const u32 as *const u8,
                buf.as_mut_ptr()
                    .add(NLMSG_OVERHEAD + std::mem::size_of::<CnMsg>()),
                std::mem::size_of::<u32>(),
            );
        }

        let addr = SockAddrNl {
            nl_family: libc::AF_NETLINK as libc::sa_family_t,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };

        let sent = unsafe {
            libc::sendto(
                sock_fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &addr as *const SockAddrNl as *const libc::sockaddr,
                std::mem::size_of::<SockAddrNl>() as u32,
            )
        };
        if sent < 0 {
            return Err(anyhow::anyhow!(
                "sendto(PROC_CN_MCAST_LISTEN) failed: {}",
                io::Error::last_os_error()
            ));
        }
        if sent as usize != buf.len() {
            return Err(anyhow::anyhow!(
                "short send for PROC_CN_MCAST_LISTEN: {} of {} bytes",
                sent,
                buf.len()
            ));
        }
        Ok(())
    }

    /// Block until one or more process events arrive, then parse and return them.
    ///
    /// This is the core "zero CPU polling" method — the kernel pushes events
    /// to us. We use a 100ms socket timeout to remain responsive to shutdown.
    pub fn recv_events(&mut self) -> Result<Vec<RawProbeEvent>> {
        let mut events = Vec::new();
        let mut buf = vec![0u8; 4096];

        loop {
            let mut addr = SockAddrNl {
                nl_family: 0,
                nl_pad: 0,
                nl_pid: 0,
                nl_groups: 0,
            };
            let mut addr_len = std::mem::size_of::<SockAddrNl>() as libc::socklen_t;

            let n = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    &mut addr as *mut SockAddrNl as *mut libc::sockaddr,
                    &mut addr_len,
                )
            };

            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut
                    || err.raw_os_error() == Some(libc::EAGAIN)
                {
                    // Timeout — no events available, break out
                    break;
                }
                // ENOBUFS or other transient errors — skip
                if err.raw_os_error() == Some(libc::ENOBUFS) {
                    break;
                }
                return Err(anyhow::anyhow!(
                    "recvfrom(NETLINK_CONNECTOR) failed: {}",
                    err
                ));
            }

            let received = n as usize;

            // P0 安全检查:connector 消息必须来自内核(nl_pid == 0)。
            // 本地非特权进程(或具备 CAP_NET_ADMIN 的进程)也能向本 socket
            // 发送伪造的 PROC_EVENT_* 消息,从而触发引擎对任意 PID 发出
            // SIGSTOP/SIGKILL —— 这构成权限提升 / DoS 原语(让安全引擎去
            // 杀掉防病毒自身或关键服务)。任何非内核来源的消息一律丢弃。
            if addr_len < std::mem::size_of::<SockAddrNl>() as libc::socklen_t
                || addr.nl_family != libc::AF_NETLINK as libc::sa_family_t
                || addr.nl_pid != 0
            {
                continue;
            }

            events.extend(Self::parse_netlink_datagram(&buf[..received]));

            // If we got events, return them; otherwise loop for more (with timeout)
            if !events.is_empty() {
                return Ok(events);
            }
            // recvfrom returned data but no process events — try again
        }

        Ok(events)
    }

    /// Parse a proc_event byte slice into a RawProbeEvent.
    fn parse_netlink_datagram(buf: &[u8]) -> Vec<RawProbeEvent> {
        let mut events = Vec::new();
        let mut offset = 0usize;

        while let Some(header_end) = offset.checked_add(NLMSG_OVERHEAD) {
            if header_end > buf.len() {
                break;
            }

            let msg_len = match read_u32(buf, offset) {
                Some(v) => v as usize,
                None => break,
            };
            let msg_type = match read_u16(buf, offset + 4) {
                Some(v) => v,
                None => break,
            };
            let msg_end = match offset.checked_add(msg_len) {
                Some(end) if msg_len >= NLMSG_OVERHEAD && end <= buf.len() => end,
                _ => break,
            };

            if msg_type == NLMSG_DONE {
                let cn_offset = header_end;
                let cn_end = match cn_offset.checked_add(std::mem::size_of::<CnMsg>()) {
                    Some(end) if end <= msg_end => end,
                    _ => break,
                };
                let idx = read_u32(buf, cn_offset);
                let val = read_u32(buf, cn_offset + 4);
                let data_len = read_u16(buf, cn_offset + 16).map(usize::from);

                if idx == Some(CN_IDX_PROC)
                    && val == Some(CN_VAL_PROC)
                    && let Some(data_len) = data_len
                    && data_len >= PROC_EVENT_HDR_SIZE
                    && let Some(data_end) = cn_end.checked_add(data_len)
                    && data_end <= msg_end
                    && let Some(event) = Self::parse_proc_event_data(&buf[cn_end..data_end])
                {
                    events.push(event);
                }
            } else if msg_type == NLMSG_ERROR {
                // Kernel error messages are not process events.
            }

            let aligned = match msg_len.checked_add(NLMSG_ALIGNTO - 1) {
                Some(v) => v & !(NLMSG_ALIGNTO - 1),
                None => break,
            };
            offset = match offset.checked_add(aligned) {
                Some(next) if next > offset => next,
                _ => break,
            };
        }

        events
    }

    /// Parse one connector event.
    ///
    /// FORK must not be emitted as EXEC: the child has not executed its target
    /// image yet. EXEC notifications are deliberately not de-duplicated because
    /// one process can successfully exec more than once without changing TGID.
    fn parse_proc_event_data(data: &[u8]) -> Option<RawProbeEvent> {
        if data.len() < PROC_EVENT_HDR_SIZE {
            return None;
        }
        // Decode the discriminant from bytes instead of creating a potentially
        // unaligned `&ProcEvent` at the cn_msg payload offset.
        let what = u32::from_ne_bytes(data[0..4].try_into().ok()?);

        match what {
            PROC_EVENT_FORK => {
                // A fork is not an exec. Emitting it as Execve gives policy an
                // empty path/comm and, worse, marking the child as known drops
                // the real EXEC event that follows. Process-tree bookkeeping
                // can consume FORK separately once ProbeType gains that event.
                None
            }
            PROC_EVENT_EXEC => {
                // exec: process_pid, process_tgid (2×i32 = 8 bytes)
                let payload = &data[PROC_EVENT_HDR_SIZE..];
                if payload.len() < 8 {
                    return None;
                }
                let thread_pid = i32::from_ne_bytes(payload[0..4].try_into().ok()?);
                let process_tgid = i32::from_ne_bytes(payload[4..8].try_into().ok()?);
                if thread_pid <= 0 || process_tgid <= 0 {
                    return None;
                }
                let pid = process_tgid as u32;

                // Enrich with /proc data since Netlink gives bare PIDs
                let comm = Self::read_proc_comm(pid);
                let path = Self::read_proc_exe(pid);
                let ppid = Self::read_proc_ppid(pid);
                let cgroup_id = Self::read_proc_cgroup_id(pid);

                Some(RawProbeEvent {
                    pid,
                    ppid,
                    comm: comm.clone(),
                    path: path.clone(),
                    event_type: ProbeType::Execve,
                    detail: format!("exec: {} ({})", comm, path),
                    cgroup_id,
                    ns_pid: pid,
                })
            }
            PROC_EVENT_EXIT => {
                let payload = &data[PROC_EVENT_HDR_SIZE..];
                if payload.len() < 8 {
                    return None;
                }
                let process_pid = i32::from_ne_bytes(payload[0..4].try_into().ok()?);
                let process_tgid = i32::from_ne_bytes(payload[4..8].try_into().ok()?);
                if process_pid <= 0 || process_tgid <= 0 || process_pid != process_tgid {
                    return None;
                }
                let pid = process_tgid as u32;
                Some(RawProbeEvent {
                    pid,
                    ppid: 0,
                    comm: String::new(),
                    path: String::new(),
                    event_type: ProbeType::Exit,
                    detail: format!("exit: pid={}", pid),
                    cgroup_id: 0,
                    ns_pid: pid,
                })
            }
            PROC_EVENT_UID => {
                // uid: process_pid, process_tgid, uid_r, uid_e (4×u32 = 16 bytes)
                let payload = &data[PROC_EVENT_HDR_SIZE..];
                if payload.len() < 16 {
                    return None;
                }
                let pid = u32::from_ne_bytes(payload[0..4].try_into().ok()?);
                let uid = u32::from_ne_bytes(payload[8..12].try_into().ok()?);
                Some(RawProbeEvent {
                    pid,
                    ppid: 0,
                    comm: String::new(),
                    path: String::new(),
                    event_type: ProbeType::CredChange {
                        old_uid: 0,
                        new_uid: uid,
                    },
                    detail: format!("uid_change: pid={} new_uid={}", pid, uid),
                    cgroup_id: 0,
                    ns_pid: pid,
                })
            }
            // Any other event type (including PROC_EVENT_NONE and GID which
            // we don't enrich here) is ignored.
            _ => None,
        }
    }

    // ─── /proc helpers (used to enrich bare PID events) ───
    //
    // These now delegate to `crate::procfs` so the /proc parsing logic lives
    // in exactly one place and shares the same comm-aware /proc/<pid>/stat
    // parser (which correctly handles process names containing spaces or
    // parentheses — see procfs::parse_ppid).

    fn read_proc_comm(pid: u32) -> String {
        crate::procfs::read_comm(pid)
    }

    fn read_proc_exe(pid: u32) -> String {
        crate::procfs::read_exe(pid)
    }

    fn read_proc_ppid(pid: u32) -> u32 {
        crate::procfs::read_ppid(pid)
    }

    fn read_proc_cgroup_id(pid: u32) -> u64 {
        // NOTE: hashing the cgroup path with DefaultHasher is not stable across
        // runs/processes (its seed is randomized) and is only suitable as a
        // best-effort de-duplication key within a single process lifetime.
        // Replacing it with a true bpf_get_current_cgroup_id()-style value is
        // tracked separately (P1).
        std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
            .ok()
            .map(|s| {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                s.hash(&mut hasher);
                hasher.finish()
            })
            .unwrap_or(0)
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    Some(u16::from_ne_bytes(buf.get(offset..end)?.try_into().ok()?))
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_ne_bytes(buf.get(offset..end)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event_bytes(what: u32, payload_words: &[i32]) -> Vec<u8> {
        let mut data = vec![0u8; PROC_EVENT_HDR_SIZE];
        data[0..4].copy_from_slice(&what.to_ne_bytes());
        for word in payload_words {
            data.extend_from_slice(&word.to_ne_bytes());
        }
        data
    }

    fn netlink_datagram(event: &[u8]) -> Vec<u8> {
        let total_len = NLMSG_OVERHEAD + std::mem::size_of::<CnMsg>() + event.len();
        let mut data = vec![0u8; total_len];
        data[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
        data[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        let cn = NLMSG_OVERHEAD;
        data[cn..cn + 4].copy_from_slice(&CN_IDX_PROC.to_ne_bytes());
        data[cn + 4..cn + 8].copy_from_slice(&CN_VAL_PROC.to_ne_bytes());
        data[cn + 16..cn + 18].copy_from_slice(&(event.len() as u16).to_ne_bytes());
        let payload = cn + std::mem::size_of::<CnMsg>();
        data[payload..].copy_from_slice(event);
        data
    }

    #[test]
    fn fork_does_not_emit_exec() {
        let fork = event_bytes(PROC_EVENT_FORK, &[10, 10, 20, 20]);

        assert!(NetlinkConnector::parse_proc_event_data(&fork).is_none());
    }

    #[test]
    fn exec_after_fork_and_reexec_are_both_emitted_by_tgid() {
        let fork = event_bytes(PROC_EVENT_FORK, &[10, 10, 21, 20]);
        let exec = event_bytes(PROC_EVENT_EXEC, &[21, 20]);

        assert!(NetlinkConnector::parse_proc_event_data(&fork).is_none());
        let emitted = NetlinkConnector::parse_proc_event_data(&exec)
            .expect("the successful EXEC must not be suppressed by FORK");
        assert_eq!(emitted.pid, 20);
        assert!(NetlinkConnector::parse_proc_event_data(&exec).is_some());
    }

    #[test]
    fn thread_exit_is_not_reported_as_process_exit() {
        let thread_exit = event_bytes(PROC_EVENT_EXIT, &[21, 20]);
        let process_exit = event_bytes(PROC_EVENT_EXIT, &[20, 20]);

        assert!(NetlinkConnector::parse_proc_event_data(&thread_exit).is_none());
        let emitted = NetlinkConnector::parse_proc_event_data(&process_exit)
            .expect("thread-group leader exit should be emitted");
        assert_eq!(emitted.pid, 20);
    }

    #[test]
    fn datagram_rejects_cn_length_past_message_boundary() {
        let event = event_bytes(PROC_EVENT_EXEC, &[20, 20]);
        let mut datagram = netlink_datagram(&event);
        let cn_len = NLMSG_OVERHEAD + 16;
        datagram[cn_len..cn_len + 2].copy_from_slice(&u16::MAX.to_ne_bytes());

        assert!(NetlinkConnector::parse_netlink_datagram(&datagram).is_empty());
    }

    #[test]
    fn datagram_rejects_truncated_and_unaligned_headers_without_panicking() {
        for len in 0..NLMSG_OVERHEAD {
            assert!(NetlinkConnector::parse_netlink_datagram(&vec![0xff; len]).is_empty());
        }

        let mut malformed = vec![0u8; NLMSG_OVERHEAD];
        malformed[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(NetlinkConnector::parse_netlink_datagram(&malformed).is_empty());
    }
}

impl Drop for NetlinkConnector {
    fn drop(&mut self) {
        let _ = Self::send_listen_cmd(self.fd.as_raw_fd(), false);
    }
}

/// Async wrapper: polls the Netlink socket with tokio, yielding CPU only when
/// waiting for kernel events. Compatible with tokio's async runtime.
pub struct AsyncNetlinkConnector {
    inner: std::sync::Arc<std::sync::Mutex<NetlinkConnector>>,
}

impl AsyncNetlinkConnector {
    pub fn new() -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(NetlinkConnector::new()?)),
        })
    }

    /// Asynchronously receive events. Blocks the async task until events arrive
    /// or the 100ms socket timeout expires.
    pub async fn recv_events_async(&self) -> Result<Vec<RawProbeEvent>> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || inner.lock().unwrap().recv_events())
            .await
            .map_err(|e| anyhow::anyhow!("Netlink async task panicked: {}", e))?
    }
}
