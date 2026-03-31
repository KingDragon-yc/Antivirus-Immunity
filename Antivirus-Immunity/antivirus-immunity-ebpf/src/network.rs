//! Network Monitor — 网络连接监控与阻断
//!
//! 生物学类比：补体系统 (Complement System)
//! 补体蛋白在血液中巡逻，发现外来入侵物时立即标记并溶解。
//! 本模块监控所有出站/入站 TCP 连接，对可疑连接进行标记或阻断。
//!
//! eBPF hooks (plan):
//! - kprobe/tcp_connect: 拦截出站 TCP 连接
//! - XDP: 入站包过滤（高性能，在 NIC 驱动层）
//! - TC: 出站包过滤

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// 连接追踪记录
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub pid: u32,
    pub comm: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub timestamp: Instant,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// 网络监控器
pub struct NetworkMonitor {
    /// 活跃连接表: (pid, dst_addr, dst_port) → record
    active: HashMap<(u32, IpAddr, u16), ConnectionRecord>,
    /// 连接速率追踪: pid → 最近N秒内的连接数
    rate_tracker: HashMap<u32, Vec<Instant>>,
    /// 速率窗口（秒）
    rate_window: Duration,
    /// 速率阈值（每窗口最大连接数）
    rate_threshold: u32,
    /// DNS 查询缓存: ip → domain (用于反查)
    dns_cache: HashMap<IpAddr, String>,
    /// 已知恶意 IP 黑名单
    blacklist: Vec<IpAddr>,
    /// 已阻断的连接计数
    blocked_count: u64,
    /// 总连接计数
    total_count: u64,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            rate_tracker: HashMap::new(),
            rate_window: Duration::from_secs(10),
            rate_threshold: 50,
            dns_cache: HashMap::new(),
            blacklist: Vec::new(),
            blocked_count: 0,
            total_count: 0,
        }
    }

    /// 记录一个新连接
    pub fn record_connection(&mut self, conn: ConnectionRecord) {
        let key = (conn.pid, conn.dst_addr, conn.dst_port);
        self.active.insert(key, conn.clone());
        self.total_count += 1;

        // 更新速率追踪
        let now = Instant::now();
        let entry = self.rate_tracker.entry(conn.pid).or_default();
        entry.push(now);
        entry.retain(|t| now.duration_since(*t) < self.rate_window);
    }

    /// 移除已关闭的连接
    pub fn remove_connection(&mut self, pid: u32, dst_addr: IpAddr, dst_port: u16) {
        self.active.remove(&(pid, dst_addr, dst_port));
    }

    /// 检查连接速率是否异常
    pub fn is_rate_exceeded(&self, pid: u32) -> bool {
        if let Some(records) = self.rate_tracker.get(&pid) {
            let now = Instant::now();
            let recent = records
                .iter()
                .filter(|t| now.duration_since(**t) < self.rate_window)
                .count();
            recent as u32 > self.rate_threshold
        } else {
            false
        }
    }

    /// 检查 IP 是否在黑名单中
    pub fn is_blacklisted(&self, addr: &IpAddr) -> bool {
        self.blacklist.contains(addr)
    }

    /// 添加 IP 到黑名单
    pub fn add_blacklist(&mut self, addr: IpAddr) {
        if !self.blacklist.contains(&addr) {
            self.blacklist.push(addr);
        }
    }

    /// 检查是否为内部反弹 Shell 特征
    /// 典型反弹 shell: 连接到外部高端口，且进程是 sh/bash
    pub fn is_reverse_shell_pattern(&self, conn: &ConnectionRecord) -> bool {
        let suspicious_comms = ["sh", "bash", "dash", "zsh", "csh", "ksh", "fish", "ash"];
        let is_shell = suspicious_comms.iter().any(|c| conn.comm.ends_with(c));
        let is_external = !conn.dst_addr.is_loopback();
        let is_high_port = conn.dst_port > 1024;

        is_shell && is_external && is_high_port && conn.direction == Direction::Outbound
    }

    /// 检查是否为 C2 通信特征（频繁短连接到同一外部地址）
    pub fn is_c2_pattern(&self, pid: u32, dst_addr: &IpAddr) -> bool {
        if dst_addr.is_loopback() {
            return false;
        }
        let count = self
            .active
            .iter()
            .filter(|((p, addr, _), _)| *p == pid && addr == dst_addr)
            .count();
        count >= 3
    }

    /// 获取进程的所有活跃连接
    pub fn get_process_connections(&self, pid: u32) -> Vec<&ConnectionRecord> {
        self.active
            .iter()
            .filter(|((p, _, _), _)| *p == pid)
            .map(|(_, v)| v)
            .collect()
    }

    /// 清理过期连接
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.active
            .retain(|_, v| now.duration_since(v.timestamp) < max_age);
        self.rate_tracker.retain(|_, v| {
            v.retain(|t| now.duration_since(*t) < self.rate_window);
            !v.is_empty()
        });
    }

    /// 获取统计信息
    pub fn stats(&self) -> String {
        format!(
            "Network: {} active connections, {} total, {} blocked, {} blacklisted IPs",
            self.active.len(),
            self.total_count,
            self.blocked_count,
            self.blacklist.len()
        )
    }

    /// 标记一个连接已被阻断
    pub fn mark_blocked(&mut self) {
        self.blocked_count += 1;
    }

    /// 缓存 DNS 解析结果
    pub fn cache_dns(&mut self, addr: IpAddr, domain: String) {
        self.dns_cache.insert(addr, domain);
    }

    /// 查询 DNS 缓存
    pub fn resolve_dns(&self, addr: &IpAddr) -> Option<&String> {
        self.dns_cache.get(addr)
    }
}
