import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Fingerprint,
  ArrowRight,
  RefreshCw,
  WifiOff,
  CheckCircle2,
  ShieldAlert
} from "lucide-react";
import logo from "../../../assets/logo.png";
import api from "../../services/apiClient";
import axios from "axios";
import { QRCodeSVG } from "qrcode.react";
import { SPRING_CONFIG, INTERACTION_STATES } from "../../theme/motion";

interface ActivationCardProps {
  onSuccess: (token: string, code: string, vpnConfig?: string) => void;
  initialToken?: string;
}

const formatActivationCode = (val: string) => {
  const cleaned = val.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
  const segments = cleaned.match(/.{1,5}/g) || [];
  return segments.join("-").slice(0, 29); // 25 chars + 4 dashes
};

interface QrStatusResponse {
  status: string;
  token?: string;
  code?: string;
  identity?: string;
}

interface QrGenerateResponse {
  token: string;
}

const ActivationCard: React.FC<ActivationCardProps> = ({ onSuccess, initialToken }) => {
  const [activeTab, setActiveTab] = useState<"ACTIVATION" | "PASSKEY" | "QR SYNC">("ACTIVATION");
  const [code, setCode] = useState(initialToken || "");
  const [isLoading, setIsLoading] = useState(false);

  // Scoped Error States
  const [activationError, setActivationError] = useState("");
  const [qrError, setQrError] = useState("");
  const [passkeyError, setPasskeyError] = useState("");

  const [success, setSuccess] = useState("");
  const [qrToken, setQrToken] = useState("");

  const handleActivate = async () => {
    if (code.length < 8) {
      setActivationError("Please enter a valid code");
      return;
    }
    
    setIsLoading(true);
    setActivationError("");
    setSuccess("");
    
    try {
      if (window.electronAPI && window.electronAPI.run_helper) {
        const resStr = await window.electronAPI.run_helper({ args: ["activate", code] });
        const data = JSON.parse(resStr) as { message: string; token: string; code_info: { code: string }; vpn_config?: string };
        setSuccess(data.message || "Activation successful");
        const finalCode = data.code_info?.code || code;
        setTimeout(() => {
          onSuccess(data.token, finalCode, data.vpn_config);
        }, 1500);
      } else {
        const response = await api.post<{
          message: string;
          token: string;
          code_info: { code: string };
          vpn_config?: string;
        }>("/api/v1/auth/activate", { code });

        setSuccess(response.data.message || "Activation successful");
        const finalCode = response.data.code_info?.code || code;

        setTimeout(() => {
          onSuccess(response.data.token, finalCode, response.data.vpn_config);
        }, 1500);
      }
    } catch (err: unknown) {
      let msg = "Unknown error occurred";
      if (axios.isAxiosError(err)) {
        msg = (err.response?.data as { error?: string })?.error || "Connection failed";
      } else if (err instanceof Error) {
        msg = err.message;
      }
      setActivationError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  const [isRefreshingQR, setIsRefreshingQR] = useState(false);
  const [qrCooldown, setQrCooldown] = useState(0);
  const [qrServerError, setQrServerError] = useState(false);

  useEffect(() => {
    if (activeTab === "QR SYNC" && !qrToken) {
      void generateQRSession();
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== "QR SYNC" || !qrToken) return;
    
    const interval = setInterval(() => {
      void (async () => {
        try {
          if (window.electronAPI && window.electronAPI.run_helper) {
            const resStr = await window.electronAPI.run_helper({ args: ["qr-status", qrToken] });
            const data = JSON.parse(resStr) as QrStatusResponse;
            if (data.status === "authorized" && data.token && data.code) {
              setSuccess("Login Successful");
              onSuccess(data.token, data.code);
            } else if (data.status === "expired") {
              setQrError("Session expired");
            }
          } else {
            const res = await api.get<QrStatusResponse>(`/api/v1/auth/qr/status/${qrToken}`);
            if (res.data.status === "authorized" && res.data.token && res.data.code) {
              setSuccess("Login Successful");
              onSuccess(res.data.token, res.data.code);
            } else if (res.data.status === "expired") {
              setQrError("Session expired");
            }
          }
        } catch {
          console.debug("Silent poll failed");
        }
      })();
    }, 2000);
    
    return () => clearInterval(interval);
  }, [activeTab, qrToken]);

  const generateQRSession = async () => {
    if (qrCooldown > 0) return;
    setIsRefreshingQR(true);
    setQrToken("");
    setQrError("");
    setQrServerError(false);
    try {
      if (window.electronAPI && window.electronAPI.run_helper) {
        const resStr = await window.electronAPI.run_helper({ args: ["qr-generate"] });
        const res = JSON.parse(resStr) as { token: string };
        setQrToken(res.token);
      } else {
        // Fallback to direct API if daemon not available (though unlikely in prod)
        let payload = {
          device_id: "unknown-desktop",
          device_name: "Desktop Client",
          os_name: "Desktop",
          os_version: "1.0.0",
          arch: "x64",
          timestamp: Date.now(),
        };

        try {
          const { invoke } = await import("@tauri-apps/api/core");
          payload.device_id = await invoke<string>("get_machine_id").catch(() => "unknown-desktop");
        } catch {
          console.warn("Machine ID fetch failed");
        }

        const res = await api.post<QrGenerateResponse>("/api/v1/auth/qr/generate", payload);
        setQrToken(res.data.token);
      }

      setQrCooldown(3);
      const timer = setInterval(() => {
        setQrCooldown(prev => {
          if (prev <= 1) {
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    } catch {
      setQrServerError(true);
      setQrError("Daemon unreachable");
    } finally {
      setIsRefreshingQR(false);
    }
  };

  const handlePasskeyAuth = async () => {
    try {
      setIsLoading(true);
      setPasskeyError("");
      const { invoke } = await import('@tauri-apps/api/core');
      const response = await invoke<{ success: boolean; token?: string; error?: string }>('start_passkey_auth');
      
      if (response.success && response.token) {
        setSuccess("Biometric verified");
        setTimeout(() => onSuccess(response.token!, "PASSKEY-AUTH"), 1000);
      } else {
        setPasskeyError(response.error || "Authentication failed");
      }
    } catch {
      setPasskeyError("Passkey not available");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen w-full p-6">
      <motion.div 
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={SPRING_CONFIG}
        data-testid="login-card"
        className="m3-card w-full max-w-[440px] p-10 flex flex-col items-center shadow-[0_50px_100px_rgba(0,0,0,0.4)] border border-white/5 relative overflow-hidden backdrop-blur-3xl"
      >
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent pointer-events-none" />

        {/* Header Section */}
        <div className="flex flex-col items-center mb-12 w-full text-center relative z-10">
          <motion.div
            whileHover={{ scale: 1.05, rotate: 5 }}
            transition={SPRING_CONFIG}
            className="bg-white/[0.03] p-5 rounded-[32px] mb-8 border border-white/5 shadow-2xl backdrop-blur-md"
          >
            <img src={logo} alt="ShadowMesh" className="w-16 h-16 object-contain filter drop-shadow-[0_0_15px_rgba(var(--primary-rgb),0.3)]" />
          </motion.div>
          <h1 className="text-4xl font-black text-white tracking-tighter uppercase leading-none">
            Shadow<span className="text-primary">Mesh</span>
          </h1>
          <div className="flex items-center gap-3 mt-4">
             <div className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_10px_rgba(var(--primary-rgb),0.5)] animate-pulse" />
             <p className="text-[10px] font-black text-text-secondary uppercase tracking-[0.4em] opacity-40">Secure Identity Core</p>
          </div>
        </div>

        {/* Tab System (M3 Tonal Button Style) */}
        <div className="flex w-full p-1 bg-white/5 rounded-full mb-8">
          {(["ACTIVATION", "PASSKEY", "QR SYNC"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                setActivationError("");
                setQrError("");
                setPasskeyError("");
                setSuccess("");
              }}
              className={`flex-1 py-3 text-xs font-bold rounded-full transition-all duration-300 ${
                activeTab === tab
                  ? "bg-primary text-white shadow-md"
                  : "text-text-secondary hover:text-white"
              }`}
            >
              {tab === "QR SYNC" ? "Scan QR" : tab.charAt(0) + tab.slice(1).toLowerCase()}
            </button>
          ))}
        </div>

        {/* Content Area */}
        <div className="w-full min-h-[220px] flex flex-col justify-center mb-8">
          <AnimatePresence mode="wait">
            {activeTab === "ACTIVATION" && (
              <motion.div
                key="activation"
                initial={{ opacity: 0, x: -20, scale: 0.98 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: 20, scale: 0.98 }}
                transition={SPRING_CONFIG}
                className="space-y-6"
              >
                <div className="flex flex-col gap-3">
                  <label className="text-[10px] font-black text-text-secondary px-2 uppercase tracking-[0.25em] opacity-50">Activation Code</label>
                  <div className="relative group">
                    <input
                      type="text"
                      placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
                      value={code}
                      onChange={(e) => setCode(formatActivationCode(e.target.value))}
                      className="w-full bg-white/[0.03] border-2 border-white/5 rounded-[24px] px-6 py-5 text-white font-mono text-lg focus:border-primary/40 focus:bg-white/[0.06] outline-none transition-all duration-300 placeholder:text-white/10 tracking-widest group-hover:border-white/10"
                      spellCheck="false"
                      autoFocus
                    />
                    <div className="absolute inset-0 rounded-[24px] bg-primary/5 opacity-0 group-focus-within:opacity-100 pointer-events-none transition-opacity duration-500 blur-xl" />
                  </div>
                </div>
                {activationError && (
                  <div className="flex items-center gap-2 text-red-400 px-1">
                    <ShieldAlert size={14} />
                    <p className="text-xs font-medium">{activationError}</p>
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === "PASSKEY" && (
              <motion.div 
                key="passkey"
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={SPRING_CONFIG}
                className="flex flex-col items-center gap-6"
              >
                <motion.button
                  whileHover={{ scale: 1.05, backgroundColor: "rgba(99, 102, 241, 0.15)" }}
                  whileTap={{ scale: 0.95 }}
                  onClick={handlePasskeyAuth}
                  disabled={isLoading}
                  className="w-24 h-24 rounded-4xl bg-primary/10 border-2 border-primary/20 flex items-center justify-center cursor-pointer transition-all duration-300 text-primary"
                >
                  <Fingerprint size={48} className={isLoading ? 'animate-pulse text-text-muted' : ''} />
                </motion.button>
                <div className="text-center">
                  <p className="text-lg font-bold text-white">Biometric Login</p>
                  <p className="text-sm text-text-secondary mt-1">Tap icon to use Fingerprint or Face ID</p>
                </div>
                {passkeyError && (
                   <p className="text-xs text-red-400 font-medium">✕ {passkeyError}</p>
                )}
              </motion.div>
            )}

            {activeTab === "QR SYNC" && (
              <motion.div 
                key="qrsync"
                initial={{ opacity: 0, x: 20, scale: 0.98 }}
                animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0, x: -20, scale: 0.98 }}
                transition={SPRING_CONFIG}
                className="flex flex-col items-center"
              >
                <div className="relative w-48 h-48 bg-white/5 border-2 border-white/5 rounded-4xl flex items-center justify-center p-6 shadow-inner">
                  {qrServerError ? (
                    <div className="flex flex-col items-center text-red-400 gap-2">
                      <WifiOff size={40} className="opacity-40" />
                      <span className="text-[10px] font-bold">Offline</span>
                    </div>
                  ) : qrToken ? (
                    <div className="bg-white p-3 rounded-2xl shadow-lg">
                      <QRCodeSVG value={`shadowmesh:qrlogin:${qrToken}`} size={140} level="M" fgColor="#0a0b10" bgColor="#ffffff" />
                    </div>
                  ) : (
                     <RefreshCw className="animate-spin text-primary/40" size={32} />
                  )}
                </div>
                <p className="text-sm text-text-secondary mt-6 text-center">Scan with your mobile app <br/>to sync account</p>
                {qrError && (
                  <p className="text-xs text-red-400 mt-4 font-medium">✕ {qrError}</p>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Footer Section */}
        <div className="w-full">
           {success && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-emerald-500/10 text-emerald-400 p-4 rounded-2xl flex items-center gap-3 mb-6"
              >
                <CheckCircle2 size={20} />
                <p className="text-sm font-bold uppercase tracking-wider">{success}</p>
              </motion.div>
           )}

           <motion.button
             whileHover={{ scale: 1.02, translateY: -2 }}
             whileTap={INTERACTION_STATES.tap}
             onClick={handleActivate}
             disabled={isLoading || (activeTab === "ACTIVATION" && code.length < 11)}
             className="m3-button-filled w-full h-16 rounded-[24px] shadow-[0_20px_40px_rgba(var(--primary-rgb),0.2)]"
           >
             {isLoading ? (
               <RefreshCw className="animate-spin" size={20} />
             ) : (
               <div className="flex items-center justify-center gap-3">
                 <span className="text-base font-black uppercase tracking-widest">Verify & Connect</span>
                 <ArrowRight size={20} />
               </div>
             )}
           </motion.button>

           {activeTab === "QR SYNC" && (
             <button
               onClick={generateQRSession}
               disabled={isRefreshingQR || qrCooldown > 0}
               className="w-full bg-transparent border-none text-text-secondary text-xs font-bold uppercase tracking-widest cursor-pointer flex items-center justify-center gap-2 mt-6 hover:text-primary transition-colors"
             >
               <RefreshCw size={14} className={isRefreshingQR ? "animate-spin" : ""} />
               {qrCooldown > 0 ? `Refresh in ${qrCooldown}s` : "New Session"}
             </button>
           )}
        </div>
      </motion.div>
    </div>
  );
};

export default ActivationCard;
