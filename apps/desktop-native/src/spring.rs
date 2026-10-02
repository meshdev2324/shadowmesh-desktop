// SPDX-FileCopyrightText: 2026 ShadowMesh Principal Engineers
// SPDX-License-Identifier: GPL-3.0-only

//! True velocity-tracked spring dynamics (design-system/03_Physics_Engine.md).
//!
//! Semi-implicit Euler integrator: position and velocity are physical state,
//! so every animation is interruptible mid-flight and retargeting preserves
//! momentum — the Apple-grade bar. Zero heap allocation per frame.

/// Tuned for the Premium Bar: elastic rebound present but overshoot never
/// exceeds 10% of travel distance (03_Physics_Engine.md §3 Elasticity).
pub const PREMIUM: SpringParams = SpringParams { stiffness: 170.0, damping_ratio: 0.78, mass: 1.0 };

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SpringParams {
    /// Spring constant k (N/m abstract units).
    pub stiffness: f32,
    /// Damping ratio ζ: <1 underdamped (bounces), 1 critically damped.
    pub damping_ratio: f32,
    /// Inertial mass m — larger values move with more "effort".
    pub mass: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Spring {
    /// Current position.
    pub pos: f32,
    /// Current velocity — carried across retargets (momentum continuity).
    pub vel: f32,
}

impl Spring {
    pub fn new(pos: f32) -> Self {
        Self { pos, vel: 0.0 }
    }

    /// Advance one fixed timestep toward `target`.
    pub fn step(&mut self, target: f32, p: SpringParams, dt: f32) {
        let damping = 2.0 * p.damping_ratio * (p.stiffness * p.mass).sqrt();
        let accel = (-p.stiffness * (self.pos - target) - damping * self.vel) / p.mass;
        self.vel += accel * dt;
        self.pos += self.vel * dt;
    }

    /// True when motion has effectively stopped near `target`.
    pub fn settled(&self, target: f32, pos_epsilon: f32, vel_epsilon: f32) -> bool {
        (self.pos - target).abs() < pos_epsilon && self.vel.abs() < vel_epsilon
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DT: f32 = 1.0 / 60.0;
    const TARGET: f32 = 1.0;

    fn simulate(steps: usize) -> (f32, f32, f32) {
        let mut s = Spring::new(0.0);
        let mut max_pos = f32::MIN;
        for _ in 0..steps {
            s.step(TARGET, PREMIUM, DT);
            max_pos = max_pos.max(s.pos);
        }
        (s.pos, s.vel, max_pos)
    }

    #[test]
    fn converges_to_target() {
        let (pos, _, _) = simulate(120);
        assert!((pos - TARGET).abs() < 0.001, "spring did not converge: pos={pos}");
    }

    #[test]
    fn overshoot_is_present_but_under_premium_limit() {
        let (_, _, max_pos) = simulate(120);
        let overshoot = max_pos - TARGET;
        assert!(overshoot > 0.0, "no elasticity at all (overdamped or broken): max={max_pos}");
        assert!(overshoot <= 0.10 * TARGET, "overshoot exceeds the 10% Premium Bar: {overshoot}");
    }

    #[test]
    fn velocity_is_carried_across_retargets() {
        // Retarget mid-flight, near peak velocity (quarter period ≈ 5 frames).
        let mut carried = Spring::new(0.0);
        for _ in 0..5 {
            carried.step(1.0, PREMIUM, DT);
        }
        assert!(carried.vel.abs() > 0.5, "spring should be moving fast");

        // A naive implementation zeroes velocity on retarget. Momentum must
        // instead shape the post-reversal trajectory.
        let mut reset = carried;
        reset.vel = 0.0;

        for _ in 0..10 {
            carried.step(-1.0, PREMIUM, DT);
            reset.step(-1.0, PREMIUM, DT);
        }

        let divergence = (carried.pos - reset.pos).abs();
        assert!(
            divergence > 0.05,
            "retargeted spring ignores incoming momentum (divergence {divergence})"
        );
    }

    #[test]
    fn settles_and_reports_settled() {
        let mut s = Spring::new(0.0);
        let mut settled_at = None;
        for i in 0..180 {
            s.step(TARGET, PREMIUM, DT);
            if s.settled(TARGET, 0.001, 0.01) {
                settled_at = Some(i);
                break;
            }
        }
        let frame = settled_at.expect("never reported settled");
        assert!(frame < 90, "settle took too long: {} frames", frame + 1);
    }

    #[test]
    fn timestep_scale_does_not_change_outcome() {
        // Same wall-clock duration at half the step size lands equally close.
        let mut coarse = Spring::new(0.0);
        let mut fine = Spring::new(0.0);
        for _ in 0..60 {
            coarse.step(TARGET, PREMIUM, 1.0 / 30.0);
        }
        for _ in 0..120 {
            fine.step(TARGET, PREMIUM, 1.0 / 60.0);
        }
        assert!(
            (coarse.pos - fine.pos).abs() < 0.02,
            "dt divergence: coarse={} fine={}",
            coarse.pos,
            fine.pos
        );
    }
}
