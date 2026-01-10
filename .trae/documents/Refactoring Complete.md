# Phase 1: Initialize Antivirus-Immunity Core

## Goal

Initialize the Rust project structure and implement a basic system sensor to verify the environment and technical feasibility.

## Implementation Steps

### 1. Project Initialization

* Create a new Rust binary project: `antivirus-immunity-core`.

* Configure `Cargo.toml`:

  * Add `windows` crate (with features: `Win32_System_Threading`, `Win32_Foundation`, `Win32_System_Diagnostics_ToolHelp`).

  * Add `tokio` for async runtime.

  * Add `anyhow` for error handling.

  * Add `clap` for CLI argument parsing.

### 2. Architecture Skeleton

* Create module structure:

  * `src/sensor/`: Responsible for collecting system events (Process, File).

  * `src/immune/`: Core logic (Self/Non-Self analysis).

  * `src/effector/`: Execution module (Kill, Quarantine).

* Create a simple `Trait` definition for `Sensor` to ensure extensibility.

### 3. "Hello World" Sensor (Process Snapshot)

* Implement a `ProcessSensor` in `src/sensor/process.rs`.

* Use `CreateToolhelp32Snapshot` (WinAPI) to list currently running processes.

* **Verification**: The program should output a list of current process names and PIDs, proving we have successfully accessed the Windows API.

### 4. Build & Verify

* Compile and run the project.

* Verify that it can correctly list system processes (like `explorer.exe`, `svchost.exe`).

