import React, { useState, useEffect } from "react";
import { ShieldAlert, Trash2, AlertTriangle, ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { sha256 } from "js-sha256";

const DuressPinConfig: React.FC = () => {
  const [pin, setPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [hasPin, setHasPin] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  useEffect(() => {
    void checkExistingPin();
  }, []);

  const checkExistingPin = async () => {
    try {
      const existing = await window.electronAPI.getDuressPin();
      setHasPin(!!existing);
    } catch (e) {
      console.error("Failed to check pin", e);
    }
  };

  const handleSave = async () => {
    setError("");
    setSuccess("");

    if (pin.length < 4 || pin.length > 6) {
      setError("PIN must be 4-6 digits");
      return;
    }

    if (pin !== confirmPin) {
      setError("PINs do not match");
      return;
    }

    setIsSaving(true);
    try {
      const pinHash = sha256(pin);
      const result = await window.electronAPI.setDuressPin(pinHash);
      
      if (result) {
        setSuccess("Duress Active");
        setHasPin(true);
        setPin("");
        setConfirmPin("");
        setTimeout(() => setIsExpanded(false), 2000);
      } else {
        setError("Failed to save");
      }
    } catch {
      setError("System fault");
    } finally {
      setIsSaving(false);
    }
  };

  const handleRemove = async () => {
    if (confirm("Disable Duress Protocol?")) {
      await window.electronAPI.setDuressPin("");
      setHasPin(false);
      setSuccess("Disabled");
    }
  };

  return (
    <div className="group">
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center justify-between p-4 rounded-2xl hover:bg-white/[0.04] transition-all duration-300 cursor-pointer border border-transparent hover:border-white/5"
      >
        <div className="flex items-center gap-4">
          <div className={`p-2.5 rounded-xl transition-all duration-500 ${hasPin ? "text-red-400 bg-red-400/10" : "text-white/20 bg-white/5"}`}>
            <ShieldAlert size={20} strokeWidth={1.5} />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-tight">Duress Protocol</div>
            <div className="text-[10px] text-white/30 font-medium">
              {hasPin ? "Active Response Layer" : "Forensic wipe on emergency PIN"}
            </div>
          </div>
        </div>
        <div className="text-white/20">
          {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
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
              <div className="flex gap-3 text-amber-500/60 bg-amber-500/5 p-3 rounded-xl border border-amber-500/10">
                <AlertTriangle size={14} className="mt-0.5 flex-shrink-0" />
                <p className="text-[9px] leading-relaxed font-medium">
                  Entering this PIN on the lock screen will silently trigger a forensic wipe. All data will be purged immediately.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <input
                  type="password"
                  placeholder="PIN"
                  data-testid="duress-pin-input"
                  value={pin}
                  onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))}
                  className="bg-black/40 border border-white/5 rounded-xl px-4 py-3 text-white font-mono text-xs focus:border-primary/50 outline-none"
                />
                <input
                  type="password"
                  placeholder="Confirm"
                  data-testid="duress-confirm-input"
                  value={confirmPin}
                  onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ""))}
                  className="bg-black/40 border border-white/5 rounded-xl px-4 py-3 text-white font-mono text-xs focus:border-primary/50 outline-none"
                />
              </div>

              <div className="flex items-center justify-between pt-2">
                 <div className="text-[9px] font-black uppercase tracking-widest text-emerald-400">
                    {success || error || ""}
                 </div>
                 <div className="flex gap-2">
                    {hasPin && (
                      <button onClick={handleRemove} className="p-3 text-white/20 hover:text-red-400 transition-colors">
                        <Trash2 size={16} />
                      </button>
                    )}
                    <button
                      onClick={handleSave}
                      disabled={isSaving || !pin}
                      className="px-6 py-2.5 bg-primary text-white text-[9px] font-black uppercase tracking-[0.2em] rounded-xl hover:scale-[1.02] active:scale-95 transition-all disabled:opacity-20"
                    >
                      {isSaving ? "Saving..." : "Deploy"}
                    </button>
                 </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default DuressPinConfig;
