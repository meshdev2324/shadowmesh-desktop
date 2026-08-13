import React, { useState } from "react";
import { AlertOctagon, ShieldAlert } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const PanicButton: React.FC = () => {
  const [showConfirm, setShowConfirm] = useState(false);
  const [stage, setStage] = useState(0);

  const initiatePanic = async () => {
    if (window.electronAPI) {
      await window.electronAPI.panicWipe({ silent: false, reason: "User triggered via UI" });
    }
  };

  return (
    <div className="relative pt-2">
      <button
        onClick={() => setShowConfirm(true)}
        className="w-full flex items-center justify-between p-4 rounded-2xl bg-red-500/[0.03] border border-red-500/10 hover:bg-red-500/[0.08] transition-all group"
      >
        <div className="flex items-center gap-4">
          <div className="p-2.5 rounded-xl text-red-500 bg-red-500/10">
            <AlertOctagon size={20} strokeWidth={1.5} />
          </div>
          <div className="text-left">
            <div className="text-sm font-bold text-white tracking-tight">Panic Protocol</div>
            <div className="text-[10px] text-red-500/50 font-medium">Instant forensic purge</div>
          </div>
        </div>
        <span className="text-[8px] font-black uppercase tracking-[0.2em] text-red-500/40 group-hover:text-red-500 transition-colors px-3 py-1 border border-red-500/10 rounded-lg">
          Initiate
        </span>
      </button>

      <AnimatePresence>
        {showConfirm && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[100] bg-black/90 backdrop-blur-xl flex items-center justify-center p-6"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className="w-full max-w-xs space-y-8 text-center"
            >
              <div className="relative inline-block">
                <div className="p-8 rounded-[40px] bg-red-500/10 text-red-500 shadow-[0_0_40px_rgba(239,68,68,0.1)]">
                  <ShieldAlert size={64} strokeWidth={1} />
                </div>
                <motion.div
                   animate={{ scale: [1, 1.2, 1], opacity: [0.3, 0.6, 0.3] }}
                   transition={{ repeat: Infinity, duration: 2 }}
                   className="absolute inset-0 rounded-[40px] border border-red-500/30"
                />
              </div>

              <div className="space-y-2">
                <h2 className="text-2xl font-black text-white uppercase tracking-tighter">Emergency Purge</h2>
                <p className="text-[11px] text-white/40 leading-relaxed font-medium">
                  This will immediately terminate the session and <span className="text-red-400">securely erase</span> all local data.
                </p>
              </div>

              <div className="space-y-4">
                {stage === 0 ? (
                   <button
                    onClick={() => setStage(1)}
                    className="w-full py-4 bg-red-500 text-white rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] hover:bg-red-600 transition-all shadow-xl shadow-red-500/20"
                  >
                    Confirm Destruction
                  </button>
                ) : (
                  <button
                    onClick={initiatePanic}
                    className="w-full py-4 bg-white text-red-600 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] hover:scale-[1.02] active:scale-95 transition-all shadow-2xl"
                  >
                    DEPLOY PANIC NOW
                  </button>
                )}

                <button
                  onClick={() => { setShowConfirm(false); setStage(0); }}
                  className="text-[9px] font-black text-white/20 uppercase tracking-[0.2em] hover:text-white transition-colors"
                >
                  Decline & Return
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default PanicButton;
