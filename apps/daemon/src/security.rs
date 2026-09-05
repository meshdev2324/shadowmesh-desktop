use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, warn};

static DEBUGGER_DETECTED: AtomicBool = AtomicBool::new(false);

/// Big-Tech Grade: Anti-Debugging & Forensic Resistance
/// Protects the daemon from being analyzed by malicious actors.
pub fn init_security_protections() {
    #[cfg(target_os = "linux")]
    {
        check_ptrace();
    }

    // Check for common reverse engineering tools in memory or env
    check_re_env();
}

#[cfg(target_os = "linux")]
fn check_ptrace() {
    use libc::{PTRACE_TRACEME, ptrace};
    use std::ptr::null_mut;

    // Standard ptrace(PTRACE_TRACEME) trick:
    // If we are already being traced, this call will fail.
    unsafe {
        if ptrace(PTRACE_TRACEME, 0, null_mut::<libc::c_void>(), null_mut::<libc::c_void>()) < 0 {
            warn!(
                "🚨 DEBUGGER DETECTED: ptrace(PTRACE_TRACEME) failed. Forensic countermeasures active."
            );
            DEBUGGER_DETECTED.store(true, Ordering::SeqCst);

            // In production, we might want to exit or degrade functionality
            if !cfg!(debug_assertions) {
                error!("🛑 Security Violation: Debugger attached. Terminating for safety.");
                std::process::exit(0xDEAD);
            }
        }
    }
}

fn check_re_env() {
    let re_indicators = ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "_JAVA_OPTIONS"];
    for &indicator in &re_indicators {
        if std::env::var(indicator).is_ok() {
            warn!("⚠️ Potential RE/Interception tool detected in env: {}", indicator);
        }
    }
}

pub fn is_under_analysis() -> bool {
    DEBUGGER_DETECTED.load(Ordering::SeqCst)
}

/// Simple XOR-based string obfuscation to prevent easy 'strings' analysis of the binary.
pub fn obfuscate_string(input: &str, key: u8) -> Vec<u8> {
    input.as_bytes().iter().map(|&b| b ^ key).collect()
}

pub fn deobfuscate_string(input: &[u8], key: u8) -> String {
    let decoded: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
    String::from_utf8_lossy(&decoded).into_owned()
}

// Pre-obfuscated keys for sensitive strings
// Key: 0x42
pub const OBFUSCATION_KEY: u8 = 0x42;

/// Obfuscated production endpoint XORed with 0x42
pub const OBFUSCATED_PROD_API: &[u8] = &[
    0x2a, 0x36, 0x36, 0x32, 0x31, 0x78, 0x6d, 0x6d, 0x23, 0x32, 0x2b, 0x6c, 0x31, 0x2a, 0x23, 0x26,
    0x2d, 0x35, 0x2f, 0x27, 0x31, 0x2a, 0x6c, 0x2d, 0x30, 0x25,
];

pub fn get_default_api_url() -> String {
    #[cfg(debug_assertions)]
    {
        "http://localhost:8080".to_string()
    }

    #[cfg(not(debug_assertions))]
    {
        // Deobfuscate production URL or environment variable
        std::env::var("SHADOWMESH_API_URL")
            .unwrap_or_else(|_| deobfuscate_string(OBFUSCATED_PROD_API, OBFUSCATION_KEY))
    }
}
