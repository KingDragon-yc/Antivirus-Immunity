use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

pub struct CytotoxicTCell;

impl CytotoxicTCell {
    /// Terminates a process by its PID.
    /// This corresponds to inducing apoptosis in a target cell.
    pub fn induce_apoptosis(pid: u32) -> Result<()> {
        unsafe {
            // 1. Open the process with permission to terminate it
            let handle: HANDLE = OpenProcess(PROCESS_TERMINATE, false, pid)
                .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Invalid handle for process {}", pid));
            }

            // 2. Terminate it
            // Exit code 1 usually indicates an error termination, but here it just means "killed by AV"
            let result = TerminateProcess(handle, 1);

            // 3. Always close the handle
            let _ = CloseHandle(handle);

            match result {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow::anyhow!(
                    "Failed to terminate process {}: {}",
                    pid,
                    e
                )),
            }
        }
    }
}
