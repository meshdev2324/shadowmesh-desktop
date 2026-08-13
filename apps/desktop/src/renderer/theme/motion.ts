/**
 * ShadowMesh Motion System - Apple-Grade Physics
 * Based on 03_Physics_Engine.md standards.
 */

export const SPRING_CONFIG = {
  stiffness: 400,
  damping: 30,
  mass: 1,
};

export const SPRING_BOUNCY = {
  stiffness: 500,
  damping: 20,
  mass: 0.8,
};

export const MICRO_TRANSITION = {
  duration: 0.15,
  ease: [0.22, 1, 0.36, 1], // Standard interruptible ease
};

export const INTERACTION_STATES = {
  tap: { scale: 0.96 },
  hover: { scale: 1.02 },
};
