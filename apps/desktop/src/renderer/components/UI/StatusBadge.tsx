import React from "react";
import { motion } from "framer-motion";

interface StatusBadgeProps {
  status: "online" | "offline" | "connecting" | "error";
  label: string;
  plan?: string;
}

const StatusBadge: React.FC<StatusBadgeProps> = ({ status, label, plan }) => {
  const configs = {
    online: {
      text: "text-emerald-500",
      dot: "bg-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.6)]",
      bg: "bg-emerald-500/10",
      border: "border-emerald-500/20",
    },
    offline: {
      text: "text-text-muted",
      dot: "bg-text-muted/40",
      bg: "bg-white/5",
      border: "border-white/5",
    },
    connecting: {
      text: "text-primary",
      dot: "bg-primary shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]",
      bg: "bg-primary/10",
      border: "border-primary/20",
    },
    error: {
      text: "text-red-500",
      dot: "bg-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)]",
      bg: "bg-red-500/10",
      border: "border-red-500/20",
    },
  };

  const config = configs[status];

  return (
    <motion.div
      layout
      className={`inline-flex items-center gap-3.5 px-6 py-2 rounded-full border backdrop-blur-xl transition-all duration-700 ${config.bg} ${config.border} ${config.text}`}
    >
      <div className="relative flex items-center justify-center">
        <div className={`w-2.5 h-2.5 rounded-full ${config.dot} transition-colors duration-1000`} />
        {status === "connecting" && (
          <motion.div
            animate={{ scale: [1, 3], opacity: [0.5, 0] }}
            transition={{ repeat: Infinity, duration: 2, ease: "easeOut" }}
            className="absolute inset-0 bg-primary rounded-full"
          />
        )}
        {status === "online" && (
          <motion.div
            animate={{ scale: [1, 2.5], opacity: [0.3, 0] }}
            transition={{ repeat: Infinity, duration: 3, ease: "easeOut" }}
            className="absolute inset-0 bg-emerald-500 rounded-full"
          />
        )}
      </div>
      <span data-testid="status-label" className="text-[9px] font-black uppercase tracking-[0.3em]">
        {label}
      </span>
      {plan && (
        <>
          <div className="w-px h-3 bg-white/10 mx-1" />
          <span className="text-[8px] font-black uppercase tracking-[0.2em] opacity-40">
            {plan}
          </span>
        </>
      )}
    </motion.div>
  );
};

export default StatusBadge;
