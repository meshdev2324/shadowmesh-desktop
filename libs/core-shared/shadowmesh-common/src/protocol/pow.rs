use crate::error::{CommonError, CommonResult};
use aws_lc_rs::digest::{Context, SHA256};
use aws_lc_rs::hmac::{self, HMAC_SHA256, Key};
use chrono::Utc;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

static THREAD_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

fn get_thread_pool() -> &'static rayon::ThreadPool {
    THREAD_POOL.get_or_init(|| {
        let total_cores = num_cpus::get();
        let num_threads = if cfg!(target_os = "android") || cfg!(target_os = "ios") {
            ((total_cores as f32) * 0.6).ceil() as usize
        } else {
            total_cores
        };
        rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("shadow-pow-{}", i))
            .num_threads(num_threads.max(1))
            .build()
            .expect("Failed to initialize PoW thread pool")
    })
}

/// Represents a Proof-of-Work challenge with its security metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoWChallenge {
    /// Unique nonce for the challenge.
    pub nonce: String,
    /// Required number of leading zero bits.
    pub difficulty: u32,
    /// Unix timestamp of challenge creation.
    pub timestamp: i64,
    /// Context for which the challenge is valid (e.g., activation, login).
    pub context: String,
    /// HMAC signature of the challenge payload.
    pub signature: String,
}

impl PoWChallenge {
    /// Parses a challenge string in the format: nonce|difficulty|timestamp|context|signature
    pub fn parse(challenge: &str) -> Option<Self> {
        let parts: Vec<&str> = challenge.split('|').collect();
        if parts.len() != 5 {
            return None;
        }

        Some(Self {
            nonce: parts[0].to_string(),
            difficulty: parts[1].parse().ok()?,
            timestamp: parts[2].parse().ok()?,
            context: parts[3].to_string(),
            signature: parts[4].to_string(),
        })
    }

    /// Verifies the HMAC signature of the challenge payload.
    pub fn verify_signature(&self, secret: &str) -> bool {
        let payload =
            format!("{}|{}|{}|{}", self.nonce, self.difficulty, self.timestamp, self.context);
        let key = Key::new(HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, payload.as_bytes());
        let expected_sig = hex::encode(tag.as_ref());
        self.signature == expected_sig
    }

    /// Checks if the challenge has exceeded its validity window.
    pub fn is_expired(&self, window_secs: i64) -> bool {
        let now = Utc::now().timestamp();
        now - self.timestamp > window_secs
    }
}

impl std::fmt::Display for PoWChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}|{}",
            self.nonce, self.difficulty, self.timestamp, self.context, self.signature
        )
    }
}

/// Solves a Proof-of-Work challenge using parallel workers.
///
/// Limits thread usage on mobile platforms to preserve responsiveness.
/// Automatically falls back to sequential execution for low difficulty to avoid overhead.
pub fn solve_pow(challenge: &str, difficulty: u32, timeout_secs: u64) -> CommonResult<String> {
    if difficulty == 0 {
        return Ok("0".to_string());
    }
    if difficulty > 32 {
        return Err(CommonError::CryptoError("Difficulty too high".into()));
    }

    // Dynamic threading threshold: difficulty < 13 is faster sequentially
    // due to thread dispatching overhead.
    if difficulty < 13 {
        return solve_pow_sequential(challenge, difficulty, timeout_secs);
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let pool = get_thread_pool();

    let target_zeros = (difficulty / 8) as usize;
    let target_bits = (difficulty % 8) as u8;
    let bit_mask = if target_bits > 0 { 0xFFu8 << (8 - target_bits) } else { 0 };

    let challenge_bytes = challenge.as_bytes();
    let cancelled = Arc::new(AtomicBool::new(false));
    let chunk_size = 2048u64;
    let total_chunks = (u64::MAX / chunk_size) as usize;

    let result = pool.install(|| {
        (0..total_chunks).into_par_iter().find_map_any(|chunk_idx| {
            let base_solution = (chunk_idx as u64) * chunk_size;

            if cancelled.load(Ordering::Relaxed) {
                return None;
            }

            // Periodically check for timeout
            if chunk_idx % 32 == 0 && start.elapsed() > timeout {
                cancelled.store(true, Ordering::Relaxed);
                return None;
            }

            let mut ctx_base = Context::new(&SHA256);
            ctx_base.update(challenge_bytes);

            let mut itoa_buf = itoa::Buffer::new();

            for solution in base_solution..(base_solution + chunk_size) {
                let sol_str = itoa_buf.format(solution);
                let sol_bytes = sol_str.as_bytes();

                let mut ctx = ctx_base.clone();
                ctx.update(sol_bytes);
                let hash = ctx.finish();
                let hash_bytes = hash.as_ref();

                // Optimized zero check
                let mut is_valid = true;
                for &byte in hash_bytes.iter().take(target_zeros) {
                    if byte != 0 {
                        is_valid = false;
                        break;
                    }
                }

                if is_valid && target_bits > 0 && (hash_bytes[target_zeros] & bit_mask) != 0 {
                    is_valid = false;
                }

                if is_valid {
                    cancelled.store(true, Ordering::Relaxed);
                    return Some(solution.to_string());
                }
            }
            None
        })
    });

    match result {
        Some(solution) => Ok(solution),
        None => Err(CommonError::PowTimeout),
    }
}

fn solve_pow_sequential(
    challenge: &str,
    difficulty: u32,
    timeout_secs: u64,
) -> CommonResult<String> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    let target_zeros = (difficulty / 8) as usize;
    let target_bits = (difficulty % 8) as u8;
    let bit_mask = if target_bits > 0 { 0xFFu8 << (8 - target_bits) } else { 0 };

    let challenge_bytes = challenge.as_bytes();

    let mut ctx_base = Context::new(&SHA256);
    ctx_base.update(challenge_bytes);

    let mut itoa_buf = itoa::Buffer::new();

    for solution in 0..u64::MAX {
        if solution % 2048 == 0 && start.elapsed() > timeout {
            return Err(CommonError::PowTimeout);
        }

        let sol_str = itoa_buf.format(solution);
        let sol_bytes = sol_str.as_bytes();

        let mut ctx = ctx_base.clone();
        ctx.update(sol_bytes);
        let hash = ctx.finish();
        let hash_bytes = hash.as_ref();

        let mut is_valid = true;
        for &byte in hash_bytes.iter().take(target_zeros) {
            if byte != 0 {
                is_valid = false;
                break;
            }
        }

        if is_valid && target_bits > 0 && (hash_bytes[target_zeros] & bit_mask) != 0 {
            is_valid = false;
        }

        if is_valid {
            return Ok(solution.to_string());
        }
    }
    Err(CommonError::PowTimeout)
}

/// Verifies a PoW solution using hardware-accelerated SHA-256.
pub fn verify_pow(challenge: &str, solution: &str, difficulty: u32) -> bool {
    let mut ctx = Context::new(&SHA256);
    ctx.update(challenge.as_bytes());
    ctx.update(solution.as_bytes());
    let hash = ctx.finish();
    let hash_bytes = hash.as_ref();

    let target_zeros = (difficulty / 8) as usize;
    let target_bits = (difficulty % 8) as u8;
    let bit_mask = if target_bits > 0 { 0xFFu8 << (8 - target_bits) } else { 0 };

    if hash_bytes.len() < target_zeros {
        return false;
    }

    for &byte in hash_bytes.iter().take(target_zeros) {
        if byte != 0 {
            return false;
        }
    }

    if target_bits > 0
        && (target_zeros >= hash_bytes.len() || (hash_bytes[target_zeros] & bit_mask) != 0)
    {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_roundtrip() {
        let challenge = "test_challenge";
        let difficulty = 8;
        let solution = solve_pow(challenge, difficulty, 5).expect("Should solve");
        assert!(verify_pow(challenge, &solution, difficulty));
    }

    #[test]
    fn test_pow_challenge_serialization() {
        let challenge = PoWChallenge {
            nonce: "nonce123".into(),
            difficulty: 10,
            timestamp: 1627384000,
            context: "test".into(),
            signature: "sig123".into(),
        };
        let s = challenge.to_string();
        assert_eq!(s, "nonce123|10|1627384000|test|sig123");
        let parsed = PoWChallenge::parse(&s).unwrap();
        assert_eq!(parsed.nonce, challenge.nonce);
        assert_eq!(parsed.difficulty, challenge.difficulty);
    }
}
