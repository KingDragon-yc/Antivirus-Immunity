use anyhow::Result;
use std::collections::HashSet;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameA, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};

use super::hash_cache::HashCache;

/// RAII wrapper for Windows HANDLE — ensures handles are always closed.
/// Biological analogy: cleanup after phagocytosis (巨噬细胞吞噬后的清理)
struct SafeHandle(HANDLE);

impl SafeHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_invalid() {
            None
        } else {
            Some(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct TollLikeReceptor {
    known_pids: HashSet<u32>,
    hash_cache: HashCache,
}

impl TollLikeReceptor {
    pub fn new() -> Self {
        Self {
            known_pids: HashSet::new(),
            hash_cache: HashCache::new(2048),
        }
    }

    /// Full snapshot of current processes
    pub fn snapshot(&mut self) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        let mut current_pids = HashSet::new();

        unsafe {
            let handle = SafeHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?)
                .ok_or_else(|| anyhow::anyhow!("Failed to create process snapshot"))?;

            let mut entry = PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(handle.raw(), &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let name = Self::extract_name(&entry);
                    let (path, hash) = self.get_process_details(pid).unwrap_or((None, None));

                    processes.push(ProcessInfo {
                        pid,
                        name,
                        path,
                        hash,
                    });

                    current_pids.insert(pid);

                    if Process32Next(handle.raw(), &mut entry).is_err() {
                        break;
                    }
                }
            }
            // SafeHandle Drop handles CloseHandle automatically
        }

        self.known_pids = current_pids;
        Ok(processes)
    }

    /// Returns (New Processes, Dead PIDs)
    pub fn scan_diff(&mut self) -> Result<(Vec<ProcessInfo>, Vec<u32>)> {
        let mut new_processes = Vec::new();
        let mut current_pids = HashSet::new();
        let mut all_current_pids = Vec::new();

        unsafe {
            let handle = SafeHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?)
                .ok_or_else(|| anyhow::anyhow!("Failed to create snapshot for diff"))?;

            let mut entry = PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(handle.raw(), &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    current_pids.insert(pid);
                    all_current_pids.push((pid, entry));

                    if Process32Next(handle.raw(), &mut entry).is_err() {
                        break;
                    }
                }
            }
            // SafeHandle Drop handles CloseHandle automatically
        }

        // 1. Detect New
        for (pid, entry) in all_current_pids {
            if !self.known_pids.contains(&pid) {
                let name = Self::extract_name(&entry);
                let (path, hash) = self.get_process_details(pid).unwrap_or((None, None));

                new_processes.push(ProcessInfo {
                    pid,
                    name,
                    path,
                    hash,
                });
            }
        }

        // 2. Detect Dead
        let dead_pids: Vec<u32> = self.known_pids.difference(&current_pids).cloned().collect();

        // Update state
        self.known_pids = current_pids;

        Ok((new_processes, dead_pids))
    }

    /// Extract process name from PROCESSENTRY32
    fn extract_name(entry: &PROCESSENTRY32) -> String {
        let end = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        String::from_utf8_lossy(&entry.szExeFile[..end]).to_string()
    }

    /// Get process path and hash with RAII handle management
    fn get_process_details(&mut self, pid: u32) -> Option<(Option<String>, Option<String>)> {
        unsafe {
            let handle = SafeHandle::new(
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?,
            )?;

            let mut buffer = [0u8; MAX_PATH as usize * 2];
            let mut size = buffer.len() as u32;

            let success = QueryFullProcessImageNameA(
                handle.raw(),
                PROCESS_NAME_FORMAT(0),
                windows::core::PSTR(buffer.as_mut_ptr()),
                &mut size,
            )
            .is_ok();
            // SafeHandle Drop handles CloseHandle automatically

            if success {
                let path = String::from_utf8_lossy(&buffer[..size as usize]).to_string();
                // Use cached hash computation
                let hash = self.hash_cache.get_or_compute(&path).ok();
                return Some((Some(path), hash));
            }
        }
        None
    }

    /// Get hash cache statistics
    pub fn cache_stats(&self) -> String {
        self.hash_cache.stats_summary()
    }
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
}
