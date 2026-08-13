import React, { useEffect, useState } from "react";
import { Cpu } from "lucide-react";

const QuantumSettings: React.FC = () => {
  const [params, setParams] = useState<{ mtu: number; tcp_mss: number } | null>(null);

  useEffect(() => {
    if (window.electronAPI) {
      void window.electronAPI.getQuantumParams().then(setParams);
    }
  }, []);

  if (!params) return null;

  return (
    <div className="m3-card-tonal p-5">
      <div className="flex items-center gap-4 mb-5">
        <div className="p-3 rounded-2xl bg-primary/20 text-primary">
          <Cpu size={22} />
        </div>
        <div>
          <div className="font-bold text-white">Quantum Fragmentation</div>
          <div className="text-xs text-text-secondary">Low-level tunnel parameters</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-white/5 p-3 rounded-2xl border border-white/5">
          <div className="text-[9px] font-black text-text-muted uppercase tracking-widest mb-1">Tunnel MTU</div>
          <div className="text-sm font-mono font-bold text-white">{params.mtu} <span className="text-[8px] text-text-secondary">bytes</span></div>
        </div>
        <div className="bg-white/5 p-3 rounded-2xl border border-white/5">
          <div className="text-[9px] font-black text-text-muted uppercase tracking-widest mb-1">TCP MSS</div>
          <div className="text-sm font-mono font-bold text-white">{params.tcp_mss} <span className="text-[8px] text-text-secondary">bytes</span></div>
        </div>
      </div>

      <p className="mt-4 text-[9px] text-text-muted leading-relaxed">
        Optimized for <span className="text-primary font-bold">X25519</span> key exchange and adaptive DPI bypass.
      </p>
    </div>
  );
};

export default QuantumSettings;
