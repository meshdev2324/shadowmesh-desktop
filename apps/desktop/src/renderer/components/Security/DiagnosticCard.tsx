import React, { useState } from "react";
import { Activity, Globe, AlertTriangle, Search } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

import { NetworkReport } from "../../../types/shadowmesh-api";

const DiagnosticCard: React.FC = () => {
  const [running, setRunning] = useState(false);
  const [report, setReport] = useState<NetworkReport | null>(null);

  const runDiagnostics = async () => {
    if (!window.electronAPI) return;
    setRunning(true);
    try {
      const result = await window.electronAPI.getNetworkReport();
      setReport(result);
    } catch (err) {
      console.error(err);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="m3-card-tonal p-5 space-y-5 border border-white/5 bg-surface/30">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-2xl bg-white/5 text-text-secondary border border-white/5">
            <Activity size={20} />
          </div>
          <div>
            <div className="font-bold text-text-primary tracking-tight">System Diagnostics</div>
            <div className="text-[11px] text-text-secondary font-medium">Deep tunnel & packet analysis</div>
          </div>
        </div>
        <button
          onClick={runDiagnostics}
          disabled={running}
          className={`px-4 py-2 rounded-xl text-xs font-bold transition-all border ${
            running
              ? "bg-primary/10 text-primary border-primary/20 animate-pulse"
              : "bg-surface text-text-secondary border-white/10 hover:border-white/20 hover:text-text-primary"
          }`}
        >
          {running ? "Analyzing..." : "Run Test"}
        </button>
      </div>

      <AnimatePresence>
        {report && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            className="pt-5 border-t border-white/5 space-y-4"
          >
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-text-muted font-semibold uppercase tracking-wider">Interface Status</span>
              <span className={`font-bold uppercase ${report?.is_connected ? "text-emerald-500" : "text-red-500"}`}>
                {report?.is_connected ? "Active" : "Down"}
              </span>
            </div>

            <div className="flex items-center justify-between text-[11px]">
              <span className="text-text-muted font-semibold uppercase tracking-wider">DPI Filtering</span>
              <span className={`font-bold uppercase ${report?.dpi_detected ? "text-amber-500" : "text-emerald-500"}`}>
                {report?.dpi_detected ? "Intercepted" : "Bypassed"}
              </span>
            </div>

            {report?.server_report && (
               <div className="bg-white/5 p-4 rounded-2xl border border-white/5">
                  <div className="flex items-center gap-2 mb-2">
                    <Globe size={14} className="text-primary" />
                    <span className="text-[10px] font-bold text-text-primary uppercase tracking-widest">Global Topology</span>
                  </div>
                  <p className="text-[11px] text-text-secondary leading-relaxed">
                    {report.server_report.geoip} <br/>
                    <span className="text-text-muted italic">{report.server_report.recommendation}</span>
                  </p>
               </div>
            )}

            {(report?.packet_loss || 0) > 0 && (
              <div className="flex items-center gap-3 text-amber-500 bg-amber-500/10 p-3 rounded-xl border border-amber-500/20">
                <AlertTriangle size={14} strokeWidth={2.5} />
                <span className="text-[11px] font-bold">Network instability ({Math.round((report?.packet_loss || 0) * 100)}% loss)</span>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {!report && !running && (
        <div className="flex items-center justify-center gap-2 py-2">
          <Search size={12} className="text-text-muted" />
          <p className="text-[11px] text-text-muted font-medium italic">Ready to verify path integrity.</p>
        </div>
      )}
    </div>
  );
};

export default DiagnosticCard;
