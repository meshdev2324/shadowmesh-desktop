import React, { useState, useEffect } from "react";
import { EyeOff, AlertTriangle, Power, ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const CamouflageSettings: React.FC = () => {
  const [isEnabled, setIsEnabled] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  useEffect(() => {
    void checkStatus();
  }, []);

  const checkStatus = async () => {
    try {
      const status = await window.electronAPI.getCamouflageStatus();
      setIsEnabled(status);
    } catch (e) {
      console.error("Failed to check camouflage", e);
    }
  };

  const toggleCamouflage = async () => {
    try {
      if (isEnabled) {
        await window.electronAPI.disableCamouflage();
        setIsEnabled(false);
      } else {
        await window.electronAPI.enableCamouflage();
        setIsEnabled(true);
      }
    } catch (err) {
      console.error("[camouflage] Failed to toggle:", err);
    }
  };

  return (
    <div className="group">
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center justify-between p-4 rounded-2xl hover:bg-white/[0.04] transition-all duration-300 cursor-pointer border border-transparent hover:border-white/5"
      >
        <div className="flex items-center gap-4">
          <div className={`p-2.5 rounded-xl transition-all duration-500 ${isEnabled ? "text-primary bg-primary/10" : "text-white/20 bg-white/5"}`}>
            <EyeOff size={20} strokeWidth={1.5} />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-tight">Visual Camouflage</div>
            <div className="text-[10px] text-white/30 font-medium">
              {isEnabled ? "App Masking Active" : "Hide app as system utility"}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
           <div className={`w-8 h-4 rounded-full relative transition-all duration-500 flex items-center px-0.5 ${
            isEnabled ? "bg-primary" : "bg-white/10"
          }`}>
            <motion.div
              animate={{ x: isEnabled ? 16 : 0 }}
              className="w-3 h-3 rounded-full bg-white shadow-sm"
            />
          </div>
          <div className="text-white/20">
            {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </div>
        </div>
      </div>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="px-4 pb-4"
          >
            <div className="bg-white/[0.02] border border-white/5 rounded-2xl p-5 space-y-6">
              <div className="flex gap-3 text-primary/60 bg-primary/5 p-3 rounded-xl border border-primary/10">
                <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
                <p className="text-[9px] leading-relaxed font-medium">
                  Masks the application as a standard calculator to bypass visual inspection. Use shortcuts for instant transition.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <span className="text-[8px] font-black text-white/20 uppercase tracking-[0.2em]">Global Hotkey</span>
                  <code className="text-[10px] text-primary font-black block">CTRL + SHIFT + X</code>
                </div>
                <div className="space-y-1 text-right">
                  <span className="text-[8px] font-black text-white/20 uppercase tracking-[0.2em]">Secret Trigger</span>
                  <code className="text-[10px] text-emerald-400 font-black block">1337 + [=]</code>
                </div>
              </div>

              <button
                onClick={toggleCamouflage}
                className={`w-full py-3 rounded-xl text-[9px] font-black uppercase tracking-[0.2em] transition-all duration-500 flex items-center justify-center gap-2 ${
                  isEnabled
                    ? "bg-red-500 text-white"
                    : "bg-primary text-white shadow-lg shadow-primary/10"
                }`}
              >
                <Power size={12} />
                {isEnabled ? "Disable Mask" : "Enable Mask"}
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default CamouflageSettings;
