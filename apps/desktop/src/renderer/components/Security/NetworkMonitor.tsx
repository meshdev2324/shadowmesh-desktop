import React, { useEffect, useState } from "react";
import { Globe, Activity, ShieldAlert } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

import { NetworkReport } from "../../../types/shadowmesh-api";

const NetworkMonitor: React.FC = () => {
  const [report, setReport] = useState<NetworkReport | null>(null);

  const fetchNetwork = async () => {
    if (window.electronAPI) {
      try {
        const data = await window.electronAPI.getNetworkReport();
        setReport(data);
      } catch (err) {
        console.error(err);
      }
    }
  };

  useEffect(() => {
    void fetchNetwork();
    const interval = setInterval(() => { void fetchNetwork(); }, 8000);
    return () => clearInterval(interval);
  }, []);

  if (!report) return null;

  const isConnected = report.is_connected;
  const latency = Math.round(report.latency_ms || 0);
  const isHighLatency = latency > 150;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="m3-card-tonal p-5 flex items-center justify-between gap-6 border-white/5 bg-surface/40 backdrop-blur-md group hover:bg-surface/60 transition-all duration-300 shadow-sm"
    >
      <div className="flex items-center gap-4 min-w-0">
        <div className="relative flex-shrink-0">
          <div className={`w-2.5 h-2.5 rounded-full transition-all duration-700 ${
            isConnected ? (isHighLatency ? "bg-amber-400" : "bg-emerald-400") : "bg-red-500"
          } ${isConnected ? "shadow-[0_0_10px_rgba(52,211,153,0.3)]" : ""}`} />
          {isConnected && !isHighLatency && (
             <motion.div
               animate={{ scale: [1, 2.8], opacity: [0.4, 0] }}
               transition={{ repeat: Infinity, duration: 2.5 }}
               className="absolute inset-0 bg-emerald-400 rounded-full"
             />
          )}
        </div>

        <div className="flex flex-col min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <Globe size={12} className="text-primary" />
            <span className="text-xs font-bold text-text-primary tracking-tight truncate">
              {report.server_report?.geoip || (isConnected ? "Secured Shadow-Path" : "Unprotected Network")}
            </span>
          </div>
          <AnimatePresence mode="wait">
            <motion.p
              key={report.server_report?.recommendation}
              initial={{ opacity: 0, x: -2 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 2 }}
              className="text-[11px] text-text-secondary font-medium truncate"
            >
              {report.server_report?.recommendation || "Analyzing network integrity..."}
            </motion.p>
          </AnimatePresence>
        </div>
      </div>

      <div className="flex items-center gap-6">
        {report.dpi_detected && (
          <motion.div
            animate={{ opacity: [1, 0.6, 1] }}
            transition={{ repeat: Infinity, duration: 2 }}
            className="flex items-center gap-1.5 text-amber-500 bg-amber-500/10 px-2.5 py-1 rounded-full border border-amber-500/20"
          >
            <ShieldAlert size={12} strokeWidth={2.5} />
            <span className="text-[9px] font-bold tracking-wider">DPI</span>
          </motion.div>
        )}

        <div className="flex flex-col items-end">
          <div className="flex items-baseline gap-1">
             <motion.span
               key={latency}
               initial={{ opacity: 0 }}
               animate={{ opacity: 1 }}
               className={`text-sm font-bold font-mono transition-colors ${
                 !isConnected ? "text-text-muted" : isHighLatency ? "text-amber-400" : "text-emerald-400"
               }`}
             >
               {latency || "--"}
             </motion.span>
             <span className="text-[10px] text-text-muted font-bold">ms</span>
          </div>
          <div className="flex items-center gap-1.5 text-text-muted/60 group-hover:text-text-muted transition-colors">
             <Activity size={10} />
             <span className="text-[10px] font-semibold uppercase tracking-tighter">Delay</span>
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default NetworkMonitor;
