import React from "react";
import { motion } from "framer-motion";
import { SPRING_CONFIG, INTERACTION_STATES } from "../../theme/motion";

interface FeatureToggleProps {
  label: string;
  desc: string;
  enabled: boolean;
  onToggle: () => void;
}

const FeatureToggle: React.FC<FeatureToggleProps> = ({ label, desc, enabled, onToggle }) => {
  return (
    <motion.div
      role="button"
      aria-pressed={enabled}
      aria-label={label}
      data-testid={`feature-toggle-${label.toLowerCase().replace(/\s+/g, "-")}`}
      whileTap={INTERACTION_STATES.tap}
      whileHover={INTERACTION_STATES.hover}
      onClick={onToggle}
      className="group flex items-center justify-between p-4 rounded-xl bg-white/[0.02] hover:bg-white/[0.04] transition-all duration-300 cursor-pointer border border-white/5 active:bg-white/[0.06]"
    >
      <div className="flex-1 pr-4">
        <h4 className="text-xs font-bold text-white tracking-tight leading-none mb-1.5 uppercase transition-colors group-hover:text-primary">
          {label}
        </h4>
        <p className="text-[10px] text-text-secondary leading-tight opacity-40 font-medium group-hover:opacity-60 transition-opacity">
          {desc}
        </p>
      </div>

      {/* Apple-Grade Physics Track */}
      <div
        className={`w-9 h-5 rounded-full relative transition-colors duration-500 flex items-center px-1 shrink-0 ${
          enabled ? "bg-primary shadow-[0_0_15px_rgba(var(--primary-rgb),0.3)]" : "bg-white/10"
        }`}
      >
        <motion.div
          animate={{ x: enabled ? 16 : 0 }}
          transition={SPRING_CONFIG}
          className="w-3 h-3 rounded-full bg-white shadow-sm ring-1 ring-black/5"
        />
      </div>
    </motion.div>
  );
};

export default FeatureToggle;
