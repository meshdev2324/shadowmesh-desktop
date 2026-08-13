import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { SPRING_CONFIG, INTERACTION_STATES } from "../../theme/motion";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color?: string;
  subValue?: string;
  testId?: string;
}

const StatCard: React.FC<StatCardProps> = ({ label, value, icon, color, subValue, testId }) => {
  return (
    <motion.div
      whileHover={{ y: -4, backgroundColor: "rgba(255,255,255,0.06)" }}
      whileTap={INTERACTION_STATES.tap}
      className="relative overflow-hidden bg-white/[0.02] backdrop-blur-2xl p-5 rounded-[32px] border border-white/5 space-y-4 hover:border-primary/30 transition-all duration-300 group shadow-2xl"
    >
      {/* Dynamic Glow Layer */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-700" />
      <div className="absolute -inset-px bg-gradient-to-br from-white/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-700 rounded-[32px] pointer-events-none" />

      <div className="relative z-10 flex items-center justify-between">
        <div
          className="p-2.5 rounded-[14px] bg-white/[0.04] border border-white/5 transition-all duration-500 group-hover:bg-primary/20 group-hover:border-primary/20 group-hover:scale-110"
          style={color ? { color: color } : { color: 'var(--primary)' }}
        >
          {React.cloneElement(icon as React.ReactElement<{ size?: number; strokeWidth?: number }>, { size: 16, strokeWidth: 1.5 })}
        </div>
        {subValue && (
          <span className="text-[10px] text-primary font-black uppercase tracking-[0.25em] opacity-40 group-hover:opacity-100 transition-all duration-500">
            {subValue}
          </span>
        )}
      </div>

      <div className="relative z-10 space-y-1">
        <div className="h-10 overflow-hidden flex items-end">
          <AnimatePresence mode="wait">
            <motion.span
              key={String(value)}
              initial={{ y: 20, opacity: 0, scale: 0.9 }}
              animate={{ y: 0, opacity: 1, scale: 1 }}
              exit={{ y: -20, opacity: 0, scale: 0.9 }}
              transition={SPRING_CONFIG}
              data-testid={testId}
              className="text-2xl font-black text-text-primary tracking-tighter block group-hover:text-white transition-colors duration-500"
            >
              {value}
            </motion.span>
          </AnimatePresence>
        </div>
        <span className="text-[9px] font-black text-text-secondary/40 uppercase tracking-[0.3em] group-hover:text-text-secondary/80 transition-all duration-500 block">
          {label}
        </span>
      </div>
    </motion.div>
  );
};

export default StatCard;
