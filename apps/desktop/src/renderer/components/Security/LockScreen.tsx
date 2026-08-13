import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, Delete, ShieldOff } from "lucide-react";
import { sha256 } from "js-sha256";

interface LockScreenProps {
  isLocked: boolean;
  onUnlock: () => void;
  onDuress: (reason: string) => void;
}

const LockScreen: React.FC<LockScreenProps> = ({ isLocked, onUnlock, onDuress }) => {
  const [enteredPin, setEnteredPin] = useState("");
  const [error, setError] = useState("");

  const handlePinEntry = async (digit: string) => {
    const newPin = enteredPin + digit;
    if (newPin.length > 6) return;
    
    setEnteredPin(newPin);

    if (newPin.length >= 4) {
      const pinHash = sha256(newPin);
      
      // 1. Check for Duress PIN
      const duressHash = await window.electronAPI.getDuressPin();
      if (duressHash && pinHash === duressHash) {
        console.error("[security] Duress PIN matched");
        onDuress("desktop_duress_pin_entry");
        return;
      }

      // 2. Check for Primary PIN
      const primaryHash = await window.electronAPI.getSecureToken("primary_pin_hash");
      if (primaryHash && pinHash === primaryHash) {
        setEnteredPin("");
        onUnlock();
      } else if (newPin.length === 6 || (primaryHash && newPin.length === primaryHash.length)) {
        // Wrong PIN
        setEnteredPin("");
        setError("Invalid PIN");
        setTimeout(() => setError(""), 2000);
      }
    }
  };

  return (
    <AnimatePresence>
      {isLocked && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[5000] bg-background flex flex-col items-center justify-center backdrop-blur-3xl"
        >
          {/* Top Lock Icon */}
          <div className="text-center mb-10">
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className="w-20 h-20 bg-primary/10 rounded-full flex items-center justify-center mx-auto mb-6 text-primary shadow-inner"
            >
              <Lock size={40} />
            </motion.div>
            <h2 className="text-2xl font-bold text-white tracking-tight">System Locked</h2>
            <p className="text-text-secondary mt-2">Enter PIN to resume session</p>
          </div>

          {/* PIN Indicators */}
          <div className="flex gap-4 mb-12">
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <motion.div
                key={i}
                animate={{
                  scale: enteredPin.length > i ? 1.2 : 1,
                  backgroundColor: enteredPin.length > i ? "#6366F1" : "rgba(255,255,255,0.1)"
                }}
                className={`w-4 h-4 rounded-full border border-white/5 transition-all duration-200`}
              />
            ))}
          </div>

          {/* Numpad (Native Android Style) */}
          <div className="grid grid-cols-3 gap-x-8 gap-y-6 max-w-[320px]">
            {["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "del"].map((val, i) => (
              <motion.button
                key={i}
                whileTap={{ scale: 0.9, backgroundColor: "rgba(255,255,255,0.1)" }}
                onClick={() => {
                  if (val === "del") setEnteredPin(prev => prev.slice(0, -1));
                  else if (val !== "") void handlePinEntry(val);
                }}
                className={`
                  w-20 h-20 rounded-full text-2xl font-bold flex items-center justify-center transition-all duration-200
                  ${val === "" ? "invisible" : "bg-white/[0.03] border border-white/5 text-white active:bg-primary/20 active:text-primary active:border-primary/30"}
                `}
              >
                {val === "del" ? <Delete size={28} /> : val}
              </motion.button>
            ))}
          </div>
          
          {error && (
            <motion.p 
              initial={{ x: -10 }} 
              animate={{ x: [10, -10, 10, 0] }}
              className="text-red-400 mt-10 font-bold uppercase text-xs tracking-[0.2em]"
            >
              {error}
            </motion.p>
          )}

          {/* Footer Emergency Info */}
          <div className="absolute bottom-10 flex flex-col items-center gap-2 opacity-30">
            <ShieldOff size={16} />
            <span className="text-[10px] font-bold uppercase tracking-[0.3em]">Secure Terminal Lockdown</span>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default LockScreen;
