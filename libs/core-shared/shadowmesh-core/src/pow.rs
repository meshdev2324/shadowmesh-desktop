use crate::ShadowMeshError;
use shadowmesh_common::protocol::pow;

/// Solves the Proof of Work challenge using an optimized parallel approach.
///
/// This function searches for a nonce that, when appended to the challenge and hashed
/// with SHA-256, results in a hash with at least `difficulty` leading zero bits.
/// On mobile devices, it limits thread usage to 60% of cores to preserve battery and UI responsiveness.
///
/// Returns `Ok((challenge, solution))` on success, or `Err(ShadowMeshError)` on failure or timeout.
pub fn solve_pow(challenge: String, difficulty: u32) -> Result<(String, String), ShadowMeshError> {
    // 30 second timeout as standard for client-side adaptive friction
    let solution = pow::solve_pow(&challenge, difficulty, 30)?;
    Ok((challenge, solution))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_solve_pow_succeeds() -> Result<(), ShadowMeshError> {
        let challenge = "shadow_test_challenge".to_string();
        let difficulty = 8; // Exactly 1 leading zero byte

        let result = solve_pow(challenge.clone(), difficulty);
        assert!(result.is_ok());

        let (_, sol) = result?;
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.update(sol.as_bytes());
        let hash = hasher.finalize();
        assert_eq!(hash[0], 0);
        Ok(())
    }

    proptest! {
        #[test]
        fn test_pow_robustness(challenge in ".*", difficulty in 0..12u32) {
            let result = solve_pow(challenge.clone(), difficulty);
            if let Ok((_, sol)) = result {
                let mut hasher = Sha256::new();
                hasher.update(challenge.as_bytes());
                hasher.update(sol.as_bytes());
                let hash = hasher.finalize();

                let target_zeros = (difficulty / 8) as usize;
                let target_bits = (difficulty % 8) as u8;
                let bit_mask = if target_bits > 0 { 0xFFu8 << (8 - target_bits) } else { 0 };

                for i in 0..target_zeros {
                    assert_eq!(hash[i], 0);
                }
                if target_bits > 0 {
                    assert_eq!(hash[target_zeros] & bit_mask, 0);
                }
            }
        }
    }
}
