use anyhow::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

/// RAII wrapper for process handle safety
struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(pid: u32) -> Result<Self> {
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                .map_err(|e| anyhow::anyhow!("Failed to open process {}: {}", pid, e))?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Invalid handle for process {}", pid));
            }

            Ok(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct CytotoxicTCell;

/// Response actions available to the effector layer
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseAction {
    /// Log only — no active intervention
    Log,
    /// Terminate the process (apoptosis)
    Terminate,
    /// Quarantine the executable file + terminate
    QuarantineAndTerminate,
}

impl CytotoxicTCell {
    /// Terminates a process by its PID.
    /// This corresponds to inducing apoptosis in a target cell.
    ///
    /// Now uses RAII handle management — the handle is ALWAYS closed,
    /// even if TerminateProcess fails or panics.
    pub fn induce_apoptosis(pid: u32) -> Result<()> {
        let handle = ProcessHandle::open(pid)?;

        unsafe {
            TerminateProcess(handle.raw(), 1)
                .map_err(|e| anyhow::anyhow!("Failed to terminate process {}: {}", pid, e))?;
        }
        // ProcessHandle::drop() will close the handle automatically
        Ok(())
    }

    /// Determine the appropriate response action based on assessment severity
    /// and current danger level
    pub fn determine_response(
        is_critical: bool,
        is_suspicious: bool,
        active_defense: bool,
    ) -> ResponseAction {
        if !active_defense {
            return ResponseAction::Log;
        }

        if is_critical {
            ResponseAction::QuarantineAndTerminate
        } else if is_suspicious {
            ResponseAction::Terminate
        } else {
            ResponseAction::Log
        }
    }
}

