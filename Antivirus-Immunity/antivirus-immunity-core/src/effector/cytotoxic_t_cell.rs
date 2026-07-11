use anyhow::Result;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    TerminateProcess,
};

/// RAII wrapper for process handle safety
struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(pid: u32) -> Result<Self> {
        unsafe {
            let handle = OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
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

    fn creation_time(&self) -> Result<u64> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe {
            GetProcessTimes(self.0, &mut creation, &mut exit, &mut kernel, &mut user)
                .map_err(|e| anyhow::anyhow!("Failed to read process creation time: {}", e))?;
        }
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
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
    pub fn induce_apoptosis(pid: u32, expected_creation_time: Option<u64>) -> Result<()> {
        let expected = expected_creation_time.ok_or_else(|| {
            anyhow::anyhow!(
                "Refusing to terminate PID {} without a process identity fingerprint",
                pid
            )
        })?;
        let handle = ProcessHandle::open(pid)?;
        let actual = handle.creation_time()?;
        if actual != expected {
            return Err(anyhow::anyhow!(
                "Refusing to terminate PID {}: process identity changed (PID reuse)",
                pid
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_time_fingerprint_is_stable_and_mismatch_is_detectable() {
        let handle = ProcessHandle::open(std::process::id()).expect("open current process");
        let first = handle.creation_time().expect("creation time");
        let second = handle.creation_time().expect("creation time again");
        assert_eq!(first, second);
        assert_ne!(first, first.wrapping_add(1));
    }
}
