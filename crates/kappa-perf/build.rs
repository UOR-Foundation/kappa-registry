//! Capture the toolchain and code-generation settings a benchmark binary was
//! built with. A measurement is attributable only to the compiler and flags
//! that produced the measured code (KAPPA-PERF-001 section 2.4), which are
//! known at build time and not at run time.

use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for var in [
        "RUSTC",
        "CARGO_ENCODED_RUSTFLAGS",
        "PROFILE",
        "OPT_LEVEL",
        "TARGET",
    ] {
        println!("cargo::rerun-if-env-changed={var}");
    }

    let rustc = std::env::var("RUSTC")?;
    let output = Command::new(&rustc).arg("--version").output()?;
    if !output.status.success() {
        return Err(format!("{rustc} --version exited with {}", output.status).into());
    }
    let version = String::from_utf8(output.stdout)?;
    println!(
        "cargo::rustc-env=KAPPA_PERF_RUSTC_VERSION={}",
        version.trim()
    );

    // CARGO_ENCODED_RUSTFLAGS separates flags with 0x1f.
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    println!(
        "cargo::rustc-env=KAPPA_PERF_RUSTFLAGS={}",
        flags
            .split('\x1f')
            .filter(|flag| !flag.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "cargo::rustc-env=KAPPA_PERF_PROFILE={}",
        std::env::var("PROFILE")?
    );
    println!(
        "cargo::rustc-env=KAPPA_PERF_OPT_LEVEL={}",
        std::env::var("OPT_LEVEL")?
    );
    println!(
        "cargo::rustc-env=KAPPA_PERF_TARGET={}",
        std::env::var("TARGET")?
    );
    Ok(())
}
