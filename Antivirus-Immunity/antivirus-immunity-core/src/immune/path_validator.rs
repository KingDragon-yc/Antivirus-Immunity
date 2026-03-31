#![allow(dead_code)]
//! Path Validator — 路径验证模块
//!
//! 替代原有的"进程名白名单"机制。通过验证可执行文件的完整路径
//! 是否位于可信目录中，结合进程名进行交叉校验，防止路径欺骗攻击。
//!
//! 生物学类比：MHC (Major Histocompatibility Complex) — 主要组织相容性复合体
//! MHC 负责验证细胞表面的"身份证"，确保展示的抗原来自合法来源。

use std::collections::HashMap;
use std::path::Path;

/// Trusted system directories where critical Windows processes should reside.
/// Any process claiming to be a system process but running from outside these
/// paths is flagged as a potential imposter (MHC mismatch).
const TRUSTED_SYSTEM_DIRS: &[&str] = &[
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows",
    r"C:\Windows\SystemApps",
    r"C:\Windows\WinSxS",
];

const TRUSTED_PROGRAM_DIRS: &[&str] = &[r"C:\Program Files", r"C:\Program Files (x86)"];

/// Maps well-known system process names to their expected parent directories.
/// If a process has one of these names but is NOT located in the expected
/// directory, it's flagged as a high-confidence imposter.
fn build_critical_process_map() -> HashMap<&'static str, Vec<&'static str>> {
    let mut map = HashMap::new();

    // Core Windows processes that should ONLY exist in System32
    map.insert("svchost.exe", vec![r"C:\Windows\System32"]);
    map.insert("csrss.exe", vec![r"C:\Windows\System32"]);
    map.insert("smss.exe", vec![r"C:\Windows\System32"]);
    map.insert("wininit.exe", vec![r"C:\Windows\System32"]);
    map.insert("services.exe", vec![r"C:\Windows\System32"]);
    map.insert("lsass.exe", vec![r"C:\Windows\System32"]);
    map.insert("winlogon.exe", vec![r"C:\Windows\System32"]);
    map.insert("explorer.exe", vec![r"C:\Windows"]);
    map.insert("dwm.exe", vec![r"C:\Windows\System32"]);
    map.insert("taskhostw.exe", vec![r"C:\Windows\System32"]);
    map.insert("conhost.exe", vec![r"C:\Windows\System32"]);
    map.insert("spoolsv.exe", vec![r"C:\Windows\System32"]);
    map.insert("SearchIndexer.exe", vec![r"C:\Windows\System32"]);

    map
}

/// Validation result from MHC path checking
#[derive(Debug, Clone)]
pub enum PathVerdict {
    /// Process path matches expected location for this process name
    Verified,
    /// Process is in a trusted system/program directory (not a critical process)
    TrustedLocation,
    /// Critical system process found OUTSIDE its expected directory — HIGH confidence malware
    Imposter { expected: String, actual: String },
    /// Process is in a non-standard location (not necessarily malicious, but noteworthy)
    UnknownLocation { path: String },
    /// Unable to determine path (process may have exited or access denied)
    NoPath,
}

pub struct PathValidator {
    critical_map: HashMap<&'static str, Vec<&'static str>>,
}

impl PathValidator {
    pub fn new() -> Self {
        Self {
            critical_map: build_critical_process_map(),
        }
    }

    /// Validate a process by its name and full path.
    /// Returns a PathVerdict indicating trust level.
    pub fn validate(&self, process_name: &str, process_path: Option<&str>) -> PathVerdict {
        let path_str = match process_path {
            Some(p) => p,
            None => return PathVerdict::NoPath,
        };

        let path = Path::new(path_str);
        let parent_dir = match path.parent() {
            Some(p) => p.to_string_lossy().to_string(),
            None => {
                return PathVerdict::UnknownLocation {
                    path: path_str.to_string(),
                }
            }
        };

        let name_lower = process_name.to_lowercase();

        // 1. Check critical process name → expected directory mapping
        if let Some(expected_dirs) = self.critical_map.get(name_lower.as_str()) {
            let in_expected = expected_dirs
                .iter()
                .any(|dir| parent_dir.eq_ignore_ascii_case(dir));

            if in_expected {
                return PathVerdict::Verified;
            } else {
                return PathVerdict::Imposter {
                    expected: expected_dirs.join(" | "),
                    actual: parent_dir,
                };
            }
        }

        // 2. Check if in any trusted directory
        let in_trusted_system = TRUSTED_SYSTEM_DIRS
            .iter()
            .any(|dir| parent_dir.to_lowercase().starts_with(&dir.to_lowercase()));
        if in_trusted_system {
            return PathVerdict::TrustedLocation;
        }

        let in_trusted_program = TRUSTED_PROGRAM_DIRS
            .iter()
            .any(|dir| parent_dir.to_lowercase().starts_with(&dir.to_lowercase()));
        if in_trusted_program {
            return PathVerdict::TrustedLocation;
        }

        // 3. Unknown location — not inherently bad, but notable
        PathVerdict::UnknownLocation {
            path: path_str.to_string(),
        }
    }

    /// Quick check: is this process name a known critical system process?
    pub fn is_critical_name(&self, name: &str) -> bool {
        self.critical_map.contains_key(name.to_lowercase().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verified_svchost() {
        let v = PathValidator::new();
        let result = v.validate("svchost.exe", Some(r"C:\Windows\System32\svchost.exe"));
        assert!(matches!(result, PathVerdict::Verified));
    }

    #[test]
    fn test_imposter_svchost() {
        let v = PathValidator::new();
        let result = v.validate("svchost.exe", Some(r"C:\Users\hacker\svchost.exe"));
        assert!(matches!(result, PathVerdict::Imposter { .. }));
    }

    #[test]
    fn test_trusted_program_files() {
        let v = PathValidator::new();
        let result = v.validate("myapp.exe", Some(r"C:\Program Files\MyApp\myapp.exe"));
        assert!(matches!(result, PathVerdict::TrustedLocation));
    }

    #[test]
    fn test_unknown_location() {
        let v = PathValidator::new();
        let result = v.validate("sketchy.exe", Some(r"C:\Temp\sketchy.exe"));
        assert!(matches!(result, PathVerdict::UnknownLocation { .. }));
    }
}
