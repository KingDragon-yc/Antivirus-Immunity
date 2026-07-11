#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::path::PathBuf;

    println!("cargo:rerun-if-changed=bpf/probes.bpf.c");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");

    // A Windows build of the workspace must not require a Linux eBPF
    // toolchain. CARGO_CFG_TARGET_OS also handles cross-target builds.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }

    let arch = match env::var("CARGO_CFG_TARGET_ARCH")?.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => return Err(format!("unsupported eBPF target architecture: {other}").into()),
    };
    let out =
        PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?).join("probes.skel.rs");

    libbpf_cargo::SkeletonBuilder::new()
        .source("bpf/probes.bpf.c")
        .clang_args([format!("-D__TARGET_ARCH_{arch}"), "-Ibpf".to_owned()])
        .build_and_generate(out)?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
