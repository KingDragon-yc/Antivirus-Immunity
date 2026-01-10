use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameA, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};

pub struct TollLikeReceptor {
    known_pids: HashSet<u32>,
}

impl TollLikeReceptor {
    pub fn new() -> Self {
        Self {
            known_pids: HashSet::new(),
        }
    }

    /// Full snapshot of current processes
    pub fn snapshot(&mut self) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();
        let mut current_pids = HashSet::new();

        unsafe {
            let handle: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Failed to create process snapshot"));
            }

            let mut entry = PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(handle, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let end = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let name = String::from_utf8_lossy(&entry.szExeFile[..end]).to_string();

                    // Only get details if we haven't seen this PID before (Optimization)
                    // Or if we are doing a fresh full snapshot
                    // For now, let's always get details for simplicity in snapshot()
                    let (path, hash) = Self::get_process_details(pid).unwrap_or((None, None));

                    processes.push(ProcessInfo {
                        pid,
                        name,
                        path,
                        hash,
                    });

                    current_pids.insert(pid);

                    if Process32Next(handle, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(handle);
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
            let handle: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Failed to create snapshot for diff"));
            }

            let mut entry = PROCESSENTRY32::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

            if Process32First(handle, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    current_pids.insert(pid);
                    all_current_pids.push((pid, entry)); // Store entry to avoid re-reading if new

                    if Process32Next(handle, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(handle);
        }

        // 1. Detect New
        for (pid, entry) in all_current_pids {
            if !self.known_pids.contains(&pid) {
                // It's new! Get details now.
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf8_lossy(&entry.szExeFile[..end]).to_string();
                let (path, hash) = Self::get_process_details(pid).unwrap_or((None, None));

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

    fn get_process_details(pid: u32) -> Option<(Option<String>, Option<String>)> {
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).ok()?;

            if handle.is_invalid() {
                return None;
            }

            let mut buffer = [0u8; MAX_PATH as usize * 2];
            let mut size = buffer.len() as u32;

            let success = QueryFullProcessImageNameA(
                handle,
                PROCESS_NAME_FORMAT(0),
                windows::core::PSTR(buffer.as_mut_ptr()),
                &mut size,
            )
            .is_ok();

            let _ = CloseHandle(handle);

            if success {
                let path = String::from_utf8_lossy(&buffer[..size as usize]).to_string();
                // Compute hash (expensive operation, do it only when needed)
                let hash = Self::compute_hash(&path).ok();
                return Some((Some(path), hash));
            }
        }
        None
    }

    fn compute_hash(path: &str) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 4096];

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
}
