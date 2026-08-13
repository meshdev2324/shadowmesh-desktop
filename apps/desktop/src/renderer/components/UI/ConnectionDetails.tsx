import React from "react";
import { Shield, Zap, Lock, Cpu } from "lucide-react";
import { motion } from "framer-motion";
import { TrafficStats } from "../../../types/shadowmesh-api";

interface ConnectionDetailsProps {
  stats: TrafficStats | null;
}

const ConnectionDetails: React.FC<ConnectionDetailsProps> = ({ stats }) => {
  if (!stats) return null;

  const mode = stats.traffic_mode || "standard";

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative overflow-hidden bg-white/[0.02] backdrop-blur-3xl p-6 rounded-[32px] border border-emerald-500/20 space-y-5"
    >
      <div className="absolute inset-0 bg-emerald-500/[0.03]" />

      <div className="relative z-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield size={16} className="text-emerald-500" />
          <span className="text-[8px] font-black text-text-secondary uppercase tracking-[0.3em]">Active Encryption Tunnel</span>
        </div>
        <div className="px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-500 text-[9px] font-black uppercase tracking-[0.2em] border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.2)]">
          Verified
        </div>
      </div>

      <div className="relative z-10 grid grid-cols-2 gap-8">
        <div className="space-y-1.5">
          <p className="text-[9px] font-black text-text-muted uppercase tracking-[0.2em]">Protocol Architecture</p>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/10">
              <Lock size={12} className="text-emerald-500" />
            </div>
            <p className="text-[11px] font-bold text-text-primary uppercase tracking-tight">WireGuard Core</p>
          </div>
        </div>
        <div className="space-y-1.5">
          <p className="text-[9px] font-black text-text-muted uppercase tracking-[0.2em]">Cipher Suite</p>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-primary/10 border border-primary/10">
              <Zap size={12} className="text-primary" />
            </div>
            <p className="text-[11px] font-bold text-text-primary uppercase tracking-tight">X25519-Poly1305</p>
          </div>
        </div>
      </div>

      <div className="relative z-10 pt-4 border-t border-white/5 space-y-4">
        <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
                <Cpu size={14} className={mode !== "normal" ? "text-primary" : "text-text-muted"} />
                <span className="text-[9px] font-black text-text-secondary uppercase tracking-widest">Traffic Mode</span>
            </div>
            <span data-testid="traffic-mode-label" className={`text-[8px] font-black uppercase tracking-widest px-3 py-1 rounded-full border transition-all duration-500 ${
                mode === "fragmented" ? "bg-primary/10 text-primary border-primary/20 shadow-[0_0_10px_rgba(var(--primary-rgb),0.2)]" :
                mode === "reality" ? "bg-amber-500/10 text-amber-500 border-amber-500/20 shadow-[0_0_10px_rgba(245,158,11,0.2)]" :
                "bg-white/5 text-text-muted border-white/5"
            }`}>
                {mode}
            </span>
        </div>

        {mode === "fragmented" && (
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-[9px] text-text-muted leading-relaxed font-medium uppercase tracking-wider"
            >
                Quantum Fragmentation active. Bypassing stateful DPI via partitioned packet scheduling.
            </motion.p>
        )}
      </div>
    </motion.div>
  );
};

export default ConnectionDetails;
