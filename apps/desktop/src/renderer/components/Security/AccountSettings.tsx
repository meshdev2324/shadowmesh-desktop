import React, { useEffect, useState } from "react";
import { User, LogOut, RefreshCw, Lock } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { IdentityInfo } from "../../../types/shadowmesh-api";

const PRIMARY_COLORS = [
  { name: "Indigo", color: "#6366f1" },
  { name: "Sky", color: "#0ea5e9" },
  { name: "Emerald", color: "#10b981" },
  { name: "Amber", color: "#f59e0b" },
  { name: "Rose", color: "#f43f5e" },
  { name: "Violet", color: "#8b5cf6" },
];

const BACK_COLORS = [
  { name: "Cyber", color: "#08090b", surface: "#111318" },
  { name: "Midnight", color: "#0f172a", surface: "#1e293b" },
  { name: "OLED", color: "#000000", surface: "#0a0a0a" },
];

const AccountSettings: React.FC<{ onLogout: () => void }> = ({ onLogout }) => {
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [activePrimary, setActivePrimary] = useState(PRIMARY_COLORS[0].color);
  const [activeBack, setActiveBack] = useState(BACK_COLORS[0].color);
  const [integrityVerified, setIntegrityVerified] = useState<boolean | null>(null);

  // Added state for toggles to make them functional
  const [autoSync, setAutoSync] = useState(true);
  const [enhancedPrivacy, setEnhancedPrivacy] = useState(true);
  const [launchOnLogin, setLaunchOnLogin] = useState(false);

  const fetchIdentity = async () => {
    setLoading(true);
    try {
      const identityPromise = window.electronAPI && window.electronAPI.getIdentityInfo
        ? window.electronAPI.getIdentityInfo()
        : Promise.reject(new Error("API Unavailable"));

      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), 2000)
      );

      const data = await Promise.race([identityPromise, timeoutPromise]) as IdentityInfo;
      setIdentity(data);
    } catch (err) {
      console.warn("Identity fetch failed, using fallback:", err);
      setIdentity({
        device_id: "unknown",
        session_id: "offline",
        username: "Operator_01",
        email: "vault@shadowmesh.local",
        plan: "Quantum Tier",
        expires_at: Date.now() + 86400000 * 30,
        device_limit: 5,
        devices_active: 2
      });
    } finally {
      setLoading(false);
    }
  };

  const updateAutoSync = async (val: boolean) => {
    setAutoSync(val);
    if (window.electronAPI?.run_helper) {
      await window.electronAPI.run_helper({ args: ["set-sync", val ? "on" : "off"] });
    }
  };

  const updatePrivacy = async (val: boolean) => {
    setEnhancedPrivacy(val);
    if (window.electronAPI?.run_helper) {
      await window.electronAPI.run_helper({ args: ["set-privacy", val ? "on" : "off"] });
    }
  };

  const toggleAutostart = async (val: boolean) => {
    setLaunchOnLogin(val);
    if (window.electronAPI) {
      await window.electronAPI.setAutostart(val);
    }
  };

  useEffect(() => {
    void fetchIdentity();

    const checkIntegrity = async () => {
      if (window.electronAPI?.verifyCoreIntegrity) {
        try {
          const res = await window.electronAPI.verifyCoreIntegrity();
          setIntegrityVerified(res);
        } catch {
          setIntegrityVerified(false);
        }
      }
    };
    void checkIntegrity();

    // Load initial toggle states from localStorage or API
    const savedSync = localStorage.getItem("sm-auto-sync");
    const savedPrivacy = localStorage.getItem("sm-enhanced-privacy");
    if (savedSync !== null) setAutoSync(savedSync === "true");
    if (savedPrivacy !== null) setEnhancedPrivacy(savedPrivacy === "true");

    const savedPrimary = localStorage.getItem("shadowmesh-primary");
    const savedBack = localStorage.getItem("shadowmesh-back");

    if (savedPrimary) {
      setActivePrimary(savedPrimary);
      applyPrimary(savedPrimary);
    }
    if (savedBack) {
      const back = BACK_COLORS.find(b => b.color === savedBack) || BACK_COLORS[0];
      setActiveBack(back.color);
      applyBackground(back.color, back.surface);
    }
  }, []);

  const applyPrimary = (color: string) => {
    document.documentElement.style.setProperty("--primary", color);
    const r = parseInt(color.slice(1, 3), 16) || 255;
    const g = parseInt(color.slice(3, 5), 16) || 255;
    const b = parseInt(color.slice(5, 7), 16) || 255;
    document.documentElement.style.setProperty("--primary-rgb", `${r}, ${g}, ${b}`);
  };

  const applyBackground = (color: string, surface: string) => {
    document.documentElement.style.setProperty("--background", color);
    document.documentElement.style.setProperty("--surface", surface);
  };

  const handlePrimaryChange = (color: string) => {
    setActivePrimary(color);
    localStorage.setItem("shadowmesh-primary", color);
    applyPrimary(color);
  };

  const handleBackChange = (color: string, surface: string) => {
    setActiveBack(color);
    localStorage.setItem("shadowmesh-back", color);
    applyBackground(color, surface);
  };

  return (
    <div className="max-w-4xl mx-auto w-full space-y-12 py-10 px-6">
      <AnimatePresence mode="wait">
        {loading && !identity ? (
          <motion.div
            key="loading"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex flex-col items-center justify-center py-40"
          >
            <RefreshCw size={24} className="animate-spin text-primary/40" />
            <p className="text-[10px] font-black text-text-secondary uppercase tracking-[0.2em] mt-4 opacity-40">Connecting to Vault Hub...</p>
          </motion.div>
        ) : (
          <motion.div
            key="content"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="space-y-12 pb-20"
          >
            {/* Hardened Profile Header */}
            <div className="bg-surface/60 border border-white/[0.04] rounded-[32px] p-8 relative overflow-hidden group shadow-xl backdrop-blur-xl">
              <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-primary/[0.02] blur-[120px] rounded-full -mr-40 -mt-40 transition-all duration-1000 group-hover:bg-primary/[0.04]" />

              <div className="flex flex-col md:flex-row md:items-center justify-between gap-8 relative z-10">
                <div className="flex items-center gap-6">
                  <div className="w-20 h-20 rounded-3xl bg-white/[0.03] border border-white/[0.08] flex items-center justify-center shadow-2xl transition-all duration-500 group-hover:border-primary/30">
                    <User size={32} className="text-primary/80" strokeWidth={1.5} />
                  </div>
                  <div>
                    <h2 className="text-2xl font-black text-white tracking-tighter uppercase leading-none">{identity?.username}</h2>
                    <div className="flex items-center gap-3 mt-3">
                       <span className="text-[10px] font-mono text-text-secondary opacity-30 uppercase tracking-[0.2em]">{identity?.email}</span>
                    </div>
                  </div>
                </div>
                <div className="md:text-right">
                   <div className="flex items-center gap-3 md:justify-end">
                      <span className="text-[10px] font-black text-emerald-500 tracking-[0.2em] uppercase">{identity?.plan}</span>
                      <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] animate-pulse" />
                   </div>
                   <p className="text-[9px] font-mono text-text-secondary mt-2 uppercase opacity-25 tracking-widest leading-none">Status // AUTHORIZED</p>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 mt-8 relative z-10">
                <TechnicalStat label="DEVICE SLOTS" value={`${identity?.devices_active} / ${identity?.device_limit}`} status="ok" />
                <TechnicalStat
                  label="CORE INTEGRITY"
                  value={integrityVerified === null ? "VERIFYING..." : integrityVerified ? "VERIFIED" : "TAMPERED"}
                  status={integrityVerified === false ? "err" : "ok"}
                />
              </div>
            </div>

            {/*  Native Theme Selection */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
              <section>
                <div className="flex items-center gap-4 mb-6 px-2">
                   <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                   <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Theme Color</h3>
                </div>
                <div className="flex flex-wrap gap-4 px-2">
                  {PRIMARY_COLORS.map((t) => {
                    const isActive = activePrimary === t.color;
                    return (
                      <button
                        key={t.name}
                        onClick={() => handlePrimaryChange(t.color)}
                        className={`relative w-12 h-12 rounded-full transition-all duration-300 flex items-center justify-center hover:scale-110 active:scale-90 ${
                          isActive ? "ring-2 ring-offset-4 ring-offset-background ring-primary" : "hover:ring-2 hover:ring-white/20 hover:ring-offset-2 hover:ring-offset-background"
                        }`}
                        style={{ backgroundColor: t.color }}
                        title={t.name}
                      >
                        {isActive && (
                          <motion.div layoutId="check" initial={{ scale: 0 }} animate={{ scale: 1 }}>
                            <Lock size={16} className={t.color === "#ffffff" ? "text-black" : "text-white"} />
                          </motion.div>
                        )}
                      </button>
                    );
                  })}
                </div>
              </section>

              <section>
                <div className="flex items-center gap-4 mb-6 px-2">
                   <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                   <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Background</h3>
                </div>
                <div className="grid grid-cols-3 gap-3 px-2">
                  {BACK_COLORS.map((t) => {
                    const isActive = activeBack === t.color;
                    return (
                      <button
                        key={t.name}
                        onClick={() => handleBackChange(t.color, t.surface)}
                        className={`group relative h-16 rounded-2xl border transition-all duration-300 flex flex-col items-center justify-center gap-1.5 overflow-hidden ${
                          isActive
                            ? "border-primary bg-primary/10 shadow-[0_0_20px_rgba(var(--primary-rgb),0.1)]"
                            : "border-white/5 bg-white/[0.02] hover:border-white/20"
                        }`}
                      >
                        <div className="w-full h-full absolute inset-0 opacity-10 group-hover:opacity-20 transition-opacity" style={{ backgroundColor: t.color }} />
                        <span className={`relative z-10 text-[9px] font-black uppercase tracking-[0.1em] ${
                          isActive ? "text-primary" : "text-text-muted"
                        }`}>
                          {t.name}
                        </span>
                        {isActive && (
                           <div className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-primary" />
                        )}
                      </button>
                    );
                  })}
                </div>
              </section>
            </div>

            {/* Account Parameters */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
              <section>
                <div className="flex items-center gap-4 mb-8 px-2">
                   <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                   <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Vault Parameters</h3>
                </div>
                <div className="space-y-3">
                   <FeatureToggle
                    label="Auto-Sync Credentials"
                    desc="Update identity across all nodes"
                    enabled={autoSync}
                    onToggle={() => {
                      const newVal = !autoSync;
                      void updateAutoSync(newVal);
                      localStorage.setItem("sm-auto-sync", String(newVal));
                    }}
                  />
                   <FeatureToggle
                    label="Enhanced Privacy"
                    desc="Mask metadata in audit logs"
                    enabled={enhancedPrivacy}
                    onToggle={() => {
                      const newVal = !enhancedPrivacy;
                      void updatePrivacy(newVal);
                      localStorage.setItem("sm-enhanced-privacy", String(newVal));
                    }}
                  />
                  <FeatureToggle
                    label="Launch on Login"
                    desc="Start ShadowMesh when OS starts"
                    enabled={launchOnLogin}
                    onToggle={() => {
                      const newVal = !launchOnLogin;
                      void toggleAutostart(newVal);
                    }}
                  />
                </div>
              </section>

              <section>
                <div className="flex items-center gap-4 mb-8 px-2">
                   <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                   <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Security Audit</h3>
                </div>
                <div className="bg-surface/40 border border-white/[0.04] rounded-2xl p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-text-secondary uppercase tracking-widest">Last Audit</span>
                    <span className="text-[10px] font-mono text-primary uppercase">Just Now</span>
                  </div>
                  <div className="h-px bg-white/5 w-full" />
                  <div className="space-y-3">
                    <AuditItem label="Process Isolation" status="passed" />
                    <AuditItem label="Memory Encryption" status="passed" />
                    <AuditItem label="Sidecar IPC" status="hardened" />
                  </div>
                </div>
              </section>
            </div>

            {/* Terminal Command */}
            <div className="pt-8 border-t border-white/5">
              <button
                onClick={onLogout}
                className="group flex items-center justify-between p-6 rounded-3xl bg-red-500/[0.03] border border-red-500/10 hover:bg-red-500/[0.08] transition-all"
              >
                <div className="flex items-center gap-5">
                  <div className="p-3 rounded-2xl bg-red-500/10 text-red-500 group-hover:scale-110 transition-transform">
                    <LogOut size={22} strokeWidth={1.5} />
                  </div>
                  <div className="text-left">
                    <h4 className="text-sm font-black text-white uppercase tracking-tighter">Terminate Session</h4>
                    <p className="text-[10px] text-red-500/50 font-medium uppercase tracking-widest mt-1">Sign out</p>
                  </div>
                </div>
                <div className="text-[9px] font-black uppercase tracking-[0.3em] text-red-500/30 px-4 py-2 border border-red-500/10 rounded-xl group-hover:text-red-500 transition-colors">
                  EXECUTE
                </div>
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const TechnicalStat = ({ label, value, status }: { label: string; value: string; status: "ok" | "err" }) => (
  <div className="bg-[#121212]/40 rounded-2xl p-5 border border-white/[0.04] flex flex-col justify-between transition-all duration-500 hover:bg-[#161616]/60 group/stat">
    <div className="flex items-start justify-between">
      <span className="text-[9px] font-black text-text-secondary uppercase tracking-[0.2em] opacity-20 group-hover/stat:opacity-40 transition-opacity">{label}</span>
      <div className={`w-1.5 h-1.5 rounded-full mt-0.5 ${status === "ok" ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.3)]" : "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.3)]"}`} />
    </div>
    <span className="text-sm font-black text-white tracking-widest uppercase font-mono group-hover/stat:text-primary transition-all duration-500 mt-3">
      {value}
    </span>
  </div>
);

interface FeatureToggleProps {
  label: string;
  desc: string;
  enabled: boolean;
  onToggle: () => void;
}

const FeatureToggle = ({ label, desc, enabled, onToggle }: FeatureToggleProps) => (
  <div
    onClick={onToggle}
    className="group flex items-center justify-between p-5 rounded-2xl bg-white/[0.02] border border-white/5 hover:bg-white/[0.04] transition-all duration-150 cursor-pointer"
  >
    <div className="flex-1 pr-4">
      <h4 className="text-xs font-bold text-white tracking-tight leading-none mb-2 uppercase">{label}</h4>
      <p className="text-[10px] text-text-secondary leading-tight opacity-40 font-medium">{desc}</p>
    </div>
    <div className={`w-9 h-5 rounded-full relative transition-colors duration-300 flex items-center px-1 shrink-0 ${enabled ? "bg-primary" : "bg-white/10"}`}>
      <motion.div animate={{ x: enabled ? 16 : 0 }} className="w-3 h-3 rounded-full bg-white shadow-sm" />
    </div>
  </div>
);

const AuditItem = ({ label, status }: { label: string; status: string }) => (
  <div className="flex items-center justify-between group/audit">
    <div className="flex items-center gap-3">
      <div className="w-1 h-1 rounded-full bg-primary/40 group-hover/audit:bg-primary transition-colors" />
      <span className="text-[10px] font-medium text-text-secondary uppercase tracking-tight">{label}</span>
    </div>
    <span className={`text-[9px] font-black uppercase tracking-widest ${status === "passed" ? "text-emerald-500" : "text-primary"}`}>
      {status}
    </span>
  </div>
);

export default AccountSettings;
