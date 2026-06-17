pub mod danger_theory;
pub mod fuzzy_hash;
pub mod memory_b_cell;
pub mod path_validator;

// Re-export
pub use danger_theory::DangerTheoryEngine;
pub use memory_b_cell::{Assessment, ImmuneSystem};

// AI Cortex now lives in the shared `antivirus-immunity-common` crate so the
// Windows (`core`) and Linux (`ebpf`) engines use the same ProcessContext,
// prompt-injection hardening, and verdict parsing. Re-export the public API
// here so existing `use immune::ai_cortex::{...}` call sites keep working.
pub use antivirus_immunity_common::ai_cortex::{AiCortex, AiCortexConfig, AiVerdict, ProcessContext};
