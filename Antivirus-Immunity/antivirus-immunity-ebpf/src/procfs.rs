//! procfs — /proc 读取助手(统一实现)
//!
//! 生物学类比：Toll 样受体的化学感应触须
//!
//! `netlink_connector`、`probe`、`process_tree` 三个模块此前各自复制了
//! 一份 `/proc/<pid>/{comm,exe,stat}` 解析逻辑,且其中 `/proc/<pid>/stat`
//! 的 ppid 解析存在同一个 bug(见 [`parse_ppid`])。本模块提供唯一的
//! 实现入口,三处统一调用,确保修复只写一次。
//!
//! 所有函数对失败(/proc 条目不存在、进程已退出、权限不足)返回空串、
//! 0 或 None,绝不 panic。

#![cfg(target_os = "linux")]

use std::fs;

/// Read `/proc/<pid>/comm` (the process name, max 15 chars in-kernel).
/// Returns an empty string if the file cannot be read.
pub fn read_comm(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Read the resolved path of `/proc/<pid>/exe` (the symlink target).
/// Returns an empty string if the link cannot be read (e.g. the process
/// has exited or we lack permission).
pub fn read_exe(pid: u32) -> String {
    fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Read the parent PID (field 4) from `/proc/<pid>/stat`. Returns 0 on any
/// failure (consistent with the prior call-site `unwrap_or(0)` assumption).
pub fn read_ppid(pid: u32) -> u32 {
    fs::read_to_string(format!("/proc/{}/stat", pid))
        .ok()
        .and_then(|s| parse_ppid(&s))
        .unwrap_or(0)
}

/// Read the process start time (field 22, clock ticks since boot) used as a
/// PID-reuse fingerprint. Mirrors `main.rs::proc_start_time`; centralized
/// here so other modules can reuse the same robust comm-skipping parser.
pub fn read_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    parse_field_after_comm(&stat, 19)?.parse().ok()
}

/// Read both the parent PID and the comm in one go (the `process_tree` module
/// needs both for ancestry walks). Reuses [`read_ppid`] / [`read_comm`] so
/// there is exactly one parser.
pub fn read_parent(pid: u32) -> Option<(u32, String)> {
    let ppid = read_ppid(pid);
    let comm = read_comm(pid);
    if ppid == 0 && comm.is_empty() {
        return None;
    }
    Some((ppid, comm))
}

// ─── pure parsers (unit-testable without /proc) ───

/// Parse the parent PID out of a `/proc/<pid>/stat` line.
///
/// **Correctness note**: the line is formatted as
/// `pid (comm) state pgrp ppid ...` — wait, actually: after `comm` the
/// fields are `state ppid pgrp session ...`, so `ppid` is at index 1.
/// (Common confusion: older code thought `ppid` was at index 3, which is
/// only true if you mis-split on spaces inside `comm`.)
///
/// The `comm` field (field 2) is parenthesized but **may itself contain
/// spaces and parentheses** (e.g. `Web Content`, `(sd-pam)`). The previous
/// implementation in three call sites did `s.splitn(5, ' ').collect()` and
/// took index 3 — which lands on `ppid` only when `comm` has no spaces.
/// As soon as `comm` contained a space, every field shifted right and the
/// parsed "ppid" became a garbage value (possibly pointing at an unrelated
/// PID), corrupting the process ancestry chain and downstream policy.
///
/// Fix (matching `proc_start_time` in `main.rs`): find the **last** `)`
/// in the line, skip past it and the following space, then take field 1.
pub fn parse_ppid(stat: &str) -> Option<u32> {
    parse_field_after_comm(stat, 1)?.parse().ok()
}

/// Return the whitespace field at `idx` of the portion of the stat line
/// **after** the closing `)` of the `comm` field. Post-comm fields are
/// 0-based from `state`: `[0]=state [1]=ppid [2]=pgrp [3]=session ... [19]=starttime`.
fn parse_field_after_comm(stat: &str, idx: usize) -> Option<&str> {
    // `rfind(')')` finds the closing paren of `comm`. Even if `comm` itself
    // contains `)` (rare but legal), the final `)` in the line is always the
    // one that closes the comm field, so `rfind` is correct. `+ 2` skips the
    // `)` and the single space that follows it.
    let close = stat.rfind(')')?;
    let after_comm = stat.get(close + 2..)?;
    after_comm.split_whitespace().nth(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ppid_normal_comm() {
        // Real-world example: pid 1, comm "systemd"
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 ...";
        assert_eq!(parse_ppid(stat), Some(0));
    }

    #[test]
    fn parse_ppid_comm_with_spaces() {
        // Regression for the old `splitn(5,' ')` bug: comm "Web Content" has
        // a space. Old code took index 3 of the space-split whole line, which
        // would land on "Content)" or similar garbage. The fixed parser uses
        // rfind(')') so the inner space is irrelevant.
        let stat = "1234 (Web Content) S 4321 1234 1234 ...";
        assert_eq!(parse_ppid(stat), Some(4321));
    }

    #[test]
    fn parse_ppid_comm_with_parens() {
        // Kernel threads sometimes have comm like "(sd-pam)". Even rarer:
        // a comm containing ')'. rfind must still find the *last* ')'.
        let stat = "999 (foo)bar) S 1 999 999 ...";
        // Here comm is "foo)bar" — the closing ')' is the last char before " S".
        // Expected ppid is field 1 after the last ')', i.e. "1".
        assert_eq!(parse_ppid(stat), Some(1));
    }

    #[test]
    fn parse_ppid_malformed_returns_none() {
        assert_eq!(parse_ppid(""), None);
        assert_eq!(parse_ppid("no parens here"), None);
    }

    #[test]
    fn starttime_at_field_19() {
        // 20 fields after comm; index 19 should be "99999".
        let stat = format!("1 (x) {}", "0 ".repeat(19) + "99999");
        assert_eq!(parse_field_after_comm(&stat, 19), Some("99999"));
    }
}
