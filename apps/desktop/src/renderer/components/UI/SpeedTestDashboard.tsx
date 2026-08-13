import React, { useState } from "react";
import { ArrowDown, ArrowUp, Activity, Play, RefreshCw } from "lucide-react";
import { motion } from "framer-motion";
import { SpeedTestResult } from "../../../types/shadowmesh-api";

const SpeedTestDashboard: React.FC = () => {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SpeedTestResult | null>(null);
  const [stage, setStage] = useState<"idle" | "latency" | "download" | "upload">("idle");

  const runTest = async () => {
    if (!window.electronAPI) return;
    setRunning(true);
    setResult(null);

    try {
      setStage("latency");
      // For a real-time feel, we could split these, but run_full_speed_test handles all
      const data = await window.electronAPI.runFullSpeedTest();
      setResult(data);
    } catch (err) {
      console.error("Speed test failed", err);
    } finally {
      setRunning(false);
      setStage("idle");
    }
  };

  return (
    <div className="m3-card-tonal p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-lg font-bold text-white tracking-tight">Performance Test</h3>
          <p className="text-[10px] text-text-secondary font-medium uppercase tracking-widest mt-0.5">End-to-End Tunnel Speed</p>
        </div>
        <button
          onClick={runTest}
          disabled={running}
          className={`px-4 py-2 rounded-2xl flex items-center gap-2 transition-all font-black text-[10px] uppercase tracking-widest ${
            running
              ? "bg-primary/20 text-primary cursor-default"
              : "bg-primary text-white shadow-lg shadow-primary/20 hover:scale-105 active:scale-95"
          }`}
        >
          {running ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} fill="currentColor" />}
          {running ? "Testing..." : "Run Test"}
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <SpeedMetric
          label="Latency"
          value={result?.latency_ms ? `${Math.round(result.latency_ms)}` : "---"}
          unit="ms"
          icon={<Activity size={16} />}
          active={stage === "latency"}
          highlight="#10b981"
        />
        <SpeedMetric
          label="Download"
          value={result?.download_bps ? (result.download_bps / (1024 * 1024)).toFixed(1) : "---"}
          unit="Mbps"
          icon={<ArrowDown size={16} />}
          active={stage === "download"}
          highlight="#6366f1"
        />
        <SpeedMetric
          label="Upload"
          value={result?.upload_bps ? (result.upload_bps / (1024 * 1024)).toFixed(1) : "---"}
          unit="Mbps"
          icon={<ArrowUp size={16} />}
          active={stage === "upload"}
          highlight="#8b5cf6"
        />
      </div>

      {running && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="bg-white/5 h-1.5 rounded-full overflow-hidden"
        >
          <motion.div
            animate={{
              x: ["-100%", "100%"],
            }}
            transition={{
              repeat: Infinity,
              duration: 1.5,
              ease: "linear"
            }}
            className="h-full w-1/3 bg-primary shadow-[0_0_10px_rgba(99,102,241,0.5)]"
          />
        </motion.div>
      )}

      {result && !running && (
        <p className="text-[9px] text-text-muted text-center italic">
          Last test completed at {new Date().toLocaleTimeString()}
        </p>
      )}
    </div>
  );
};

interface SpeedMetricProps {
  label: string;
  value: string;
  unit: string;
  icon: React.ReactNode;
  active: boolean;
  highlight: string;
}

const SpeedMetric = ({ label, value, unit, icon, active, highlight }: SpeedMetricProps) => (
  <div className={`m3-card-tonal p-4 flex flex-col items-center gap-2 border transition-all duration-500 ${
    active ? "border-primary bg-primary/10" : "border-white/5"
  }`}>
    <div className="p-2 rounded-xl bg-white/5 text-text-secondary" style={{ color: active ? highlight : undefined }}>
      {icon}
    </div>
    <div className="flex flex-col items-center">
      <span className="text-[9px] font-black text-text-muted uppercase tracking-widest">{label}</span>
      <div className="flex items-baseline gap-1">
        <span className="text-xl font-black text-white">{value}</span>
        <span className="text-[8px] font-bold text-text-secondary uppercase">{unit}</span>
      </div>
    </div>
  </div>
);

export default SpeedTestDashboard;
