import React, { useState, useEffect } from "react";
import { RefreshCw } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const SmartFallback: React.FC = () => {
  const [enabled, setEnabled] = useState(false);
  const [currentMode, setCurrentMode] = useState<"wireguard" | "singbox">("wireguard");

  useEffect(() => {
    if (window.electronAPI) {
      void window.electronAPI.getSmartFallbackStatus().then(status => {
        setEnabled(status.enabled);
        setCurrentMode(status.current_mode);
      });
    }
  }, []);

  const toggleFallback = async () => {
    if (!window.electronAPI) return;
    const next = !enabled;
    setEnabled(next);
    if (next) {
      await window.electronAPI.enableSmartFallback({
        enabled: true,
        wg_config_path: "auto",
        singbox_config_path: "auto",
        check_interval_sec: 30,
        handshake_timeout_sec: 10,
        auto_switch: true,
        current_mode: "wireguard"
      });
    } else {
      await window.electronAPI.disableSmartFallback();
    }
  };

  return (
    <div className="group space-y-2">
      <div
        onClick={toggleFallback}
        className="flex items-center justify-between p-4 rounded-2xl hover:bg-white/[0.04] transition-all duration-300 cursor-pointer border border-transparent hover:border-white/5"
      >
        <div className="flex items-center gap-4">
          <div className={`p-2.5 rounded-xl transition-all duration-500 ${enabled ? "text-amber-400 bg-amber-400/10" : "text-white/20 bg-white/5"}`}>
            <RefreshCw size={20} strokeWidth={1.5} className={enabled && currentMode === "singbox" ? "animate-spin" : ""} />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-tight">Adaptive Fallback</div>
            <div className="text-[10px] text-white/30 font-medium">Auto DPI circumvention</div>
          </div>
        </div>
        <div
          className={`w-10 h-5 rounded-full relative transition-all duration-500 flex items-center px-1 ${
            enabled ? "bg-amber-500" : "bg-white/10"
          }`}
        >
          <motion.div
            animate={{ x: enabled ? 20 : 0 }}
            transition={{ type: "spring", stiffness: 500, damping: 30 }}
            className="w-3 h-3 rounded-full bg-white shadow-sm"
          />
        </div>
      </div>

      <AnimatePresence>
        {enabled && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="px-4 pb-4"
          >
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[8px] font-black text-white/20 uppercase tracking-[0.2em]">Active Path</span>
                <div className="flex items-center gap-1.5">
                  <div className={`w-1 h-1 rounded-full ${currentMode === "wireguard" ? "bg-emerald-400" : "bg-amber-400"} animate-pulse`} />
                  <span className={`text-[9px] font-black uppercase ${currentMode === "wireguard" ? "text-emerald-400" : "text-amber-400"}`}>
                    {currentMode === "wireguard" ? "Standard UDP" : "Obfuscated TLS"}
                  </span>
                </div>
              </div>
              <p className="text-[9px] text-white/30 leading-relaxed">
                {currentMode === "wireguard"
                  ? "Direct path active. Monitoring for regional interference or packet filtering."
                  : "DPI interference detected. Secure VLESS tunnel established via port 443."}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default SmartFallback;
