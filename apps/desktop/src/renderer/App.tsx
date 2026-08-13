// ShadowMesh App - Android Native Style (Material 3)
import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Zap,
  Power,
  ShieldOff,
  Activity,
  LayoutGrid,
  ChevronRight,
  ShieldCheck,
  Lock,
  User,
} from "lucide-react";
import DuressPinConfig from "./components/Security/DuressPinConfig";
import CamouflageSettings from "./components/Security/CamouflageSettings";
import LockScreen from "./components/Security/LockScreen";
import DecoyLayout from "./components/Layout/DecoyLayout";
import ActivationCard from "./components/Auth/ActivationCard";
import StatCard from "./components/UI/StatCard";
import StatusBadge from "./components/UI/StatusBadge";
import ConnectionDetails from "./components/UI/ConnectionDetails";
import NetworkMonitor from "./components/Security/NetworkMonitor";
import SecurityEventsList from "./components/Security/SecurityEventsList";
import DiagnosticCard from "./components/Security/DiagnosticCard";
import LogViewer from "./components/Security/LogViewer";
import PanicButton from "./components/Security/PanicButton";
import SmartFallback from "./components/Security/SmartFallback";
import DeviceIdentity from "./components/Security/DeviceIdentity";
import AccountSettings from "./components/Security/AccountSettings";
import FeatureToggle from "./components/UI/FeatureToggle";
import { SPRING_CONFIG } from "./theme/motion";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";

import api from "./services/apiClient";
import type { ElectronAPI, TrafficStats, ServerNode } from "../types/shadowmesh-api";

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}


type DashTab = "vpn" | "features" | "settings";

const INITIAL_SERVERS: ServerNode[] = [
  { id: "1", name: "US-East-1", location: "Virginia, USA", country_code: "US", public_ip: "1.2.3.4", flag: "🇺🇸", ping: 0 },
  { id: "2", name: "EU-West-2", location: "Frankfurt, DE", country_code: "DE", public_ip: "5.6.7.8", flag: "🇩🇪", ping: 0 },
  { id: "3", name: "SG-Asia-1", location: "Singapore", country_code: "SG", public_ip: "9.10.11.12", flag: "🇸🇬", ping: 0 },
];

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [connStatus, setConnStatus] = useState<"disconnected" | "connecting_direct" | "connecting_fragmented" | "connecting_reality" | "connected" | "error">("disconnected");
  const [connStateLabel, setConnStateLabel] = useState("Disconnected");
  const [dashTab, setDashTab] = useState<DashTab>("vpn");
  const [servers, setServers] = useState<ServerNode[]>(INITIAL_SERVERS);
  const [selectedServer, setSelectedServer] = useState("1");
  const [plan, setPlan] = useState("Solo");
  const [killSwitch, setKillSwitch] = useState(true);
  const [isLocked, setIsLocked] = useState(false);
  const [isWiped, setIsWiped] = useState(false);
  const [isCamouflaged, setIsCamouflaged] = useState(false);
  const [obfuscation, setObfuscation] = useState(false);
  const [trafficModePreference] = useState<"auto" | "standard" | "reality">("auto");

  const [isResizing, setIsResizing] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [trafficStats, setTrafficStats] = useState<TrafficStats | null>(null);
  const [daemonOnline, setDaemonOnline] = useState(true);
  const [integrityVerified, setIntegrityVerified] = useState(true);
  const [deepLinkToken, setDeepLinkToken] = useState<string | null>(null);

  const updateWindowSize = async (tab: DashTab, forceCollapse = false) => {
    // Set tab first to ensure UI responsiveness even if window API fails
    setDashTab(tab);

    try {
      const appWindow = getCurrentWindow();
      const factor = await appWindow.scaleFactor();
      const currentSize = await appWindow.innerSize();
      const currentWidth = currentSize.width / factor;

      // Only the VPN tab supports the wide side-by-side node selection layout
      const shouldBeWide = tab === "vpn" && !forceCollapse;
      const targetWidth = shouldBeWide ? 920 : 420;
      const targetHeight = 840;

      if (Math.abs(currentWidth - targetWidth) > 10) {
        setIsResizing(true);

        if (targetWidth > 600) {
          // Expanding
          await appWindow.setSize(new LogicalSize(targetWidth, targetHeight));
          await new Promise(r => setTimeout(r, 50));
          setIsExpanded(true);
          setTimeout(() => setIsResizing(false), 300);
        } else {
          // Collapsing
          setIsExpanded(false);
          setTimeout(async () => {
            await appWindow.setSize(new LogicalSize(targetWidth, targetHeight));
            setTimeout(() => setIsResizing(false), 400);
          }, 150);
        }
      }
    } catch (err) {
      console.warn("Window management unavailable:", err);
      if (typeof window !== "undefined") setIsResizing(false);
    }
  };

  const handleTabChange = (tab: DashTab, forceCollapse = false) => {
    void updateWindowSize(tab, forceCollapse);
  };

  useEffect(() => {
    // Theme Restoration
    const savedPrimary = localStorage.getItem("shadowmesh-primary");
    const savedBack = localStorage.getItem("shadowmesh-back");

    if (savedPrimary) {
      document.documentElement.style.setProperty("--primary", savedPrimary);
      const r = parseInt(savedPrimary.slice(1, 3), 16) || 99;
      const g = parseInt(savedPrimary.slice(3, 5), 16) || 102;
      const b = parseInt(savedPrimary.slice(5, 7), 16) || 241;
      document.documentElement.style.setProperty("--primary-rgb", `${r}, ${g}, ${b}`);
    } else {
      document.documentElement.style.setProperty("--primary-rgb", "99, 102, 241");
    }

    if (savedBack) {
      document.documentElement.style.setProperty("--background", savedBack);
      const surface = savedBack === "#000000" ? "#0a0a0a" :
                      savedBack === "#0f172a" ? "#1e293b" :
                      savedBack === "#121212" ? "#1a1a1a" : "#111318";
      document.documentElement.style.setProperty("--surface", surface);
    }

    if (window.electronAPI) {
      window.electronAPI.onVPNStatusChanged((status) => {
        setConnStatus(status.connected ? "connected" : "disconnected");
        setConnStateLabel(status.state);
      });
      if (window.electronAPI.onCamouflageToggled) {
        window.electronAPI.onCamouflageToggled((enabled) => setIsCamouflaged(enabled));
      }
      if (window.electronAPI.onTrafficStatsChanged) {
        window.electronAPI.onTrafficStatsChanged((stats: TrafficStats) => {
          setTrafficStats(stats);
          if (stats.plan) setPlan(stats.plan);
        });
      }
      if (window.electronAPI.onDaemonStatusChanged) {
        window.electronAPI.onDaemonStatusChanged((online) => setDaemonOnline(online));
      }
      window.electronAPI.onDeepLinkReceived((token) => {
        setIsAuthenticated(false);
        setDeepLinkToken(token);
        setDashTab("vpn");
      });
      window.electronAPI.onTriggerConnect((nodeId) => {
        setSelectedServer(nodeId);
        void toggleVPN();
      });
      void window.electronAPI.verifyCoreIntegrity().then(setIntegrityVerified);
      void window.electronAPI.getSecureToken("vpn_desktop_token").then((token) => {
        if (token) setIsAuthenticated(true);
      });

      // E2E Support: Forensic Screen Trigger
      window.addEventListener("TEST_TRIGGER_FORENSIC", () => setIsWiped(true));
    }
    void updateWindowSize(dashTab);
    void fetchAndPingServers();
  }, []);

  const fetchAndPingServers = async () => {
    try {
      const { data } = await api.get<ServerNode[]>("/api/servers/ping");
      const mapped = data.map((s) => ({
        ...s,
        ping: 0,
        flag: s.country_code === "US" ? "🇺🇸" : s.country_code === "SG" ? "🇸🇬" : s.country_code === "DE" ? "🇩🇪" : "🌐",
      }));
      setServers(mapped);

      // Shadow-Router: Select best node automatically if none selected
      if (window.electronAPI && mapped.length > 0) {
        const best = await window.electronAPI.getBestNode(mapped);
        if (best) setSelectedServer(best.id);
      }

      mapped.forEach((server) => {
        void (async () => {
          if (window.electronAPI) {
            const latency = await window.electronAPI.pingServer(server.public_ip);
            setServers((prev) => prev.map((s) => s.id === server.id ? { ...s, ping: latency } : s));
          }
        })();
      });
    } catch (e) {
      console.error("Failed to fetch servers", e);
    }
  };

  const toggleVPN = async () => {
    if (connStatus === "disconnected") {
      setConnStatus("connecting_direct");
      const server = servers.find((s) => s.id === selectedServer);
      if (!server) return;

      const result = await window.electronAPI.connectVPN({
        serverId: server.id,
        mode: trafficModePreference === "auto" ? "standard" : trafficModePreference
      });
      if (result.success) setConnStatus("connected");
      else setConnStatus("error");
    } else {
      await window.electronAPI.disconnectVPN();
      setConnStatus("disconnected");
    }
  };

  const handleKillSwitchToggle = async () => {
    if (!window.electronAPI) return;
    const newState = !killSwitch;
    setKillSwitch(newState);
    if (newState) await window.electronAPI.enableKillSwitch();
    else await window.electronAPI.disableKillSwitch();
  };

  const handleObfuscationToggle = async () => {
    if (!window.electronAPI) return;
    const newState = !obfuscation;
    setObfuscation(newState);
    if (newState) {
      await window.electronAPI.startObfuscation({
        enabled: true,
        server_ip: currentServer?.public_ip || "",
        local_port: 1080,
        remote_port: 443
      });
    } else {
      await window.electronAPI.stopObfuscation();
    }
  };

  const handlePanicWipe = async () => {
    setIsWiped(true);
    if (window.electronAPI) {
      await window.electronAPI.panicWipe({ silent: true, reason: "Forensic Trigger" });
    }
  };

  const handleActivationSuccess = async (token: string) => {
    if (window.electronAPI) {
      await window.electronAPI.setSecureToken("vpn_desktop_token", token);
    }
    setIsAuthenticated(true);
  };

  if (isWiped) {
    return (
      <div data-testid="forensic-error-screen" className="w-full h-screen bg-black flex items-center justify-center p-12 font-mono">
        <div className="max-w-md space-y-6">
          <h1 className="text-red-500 text-xl font-bold">FATAL_SYSTEM_ERROR: 0x8004210B</h1>
          <p className="text-white/40 text-xs leading-relaxed">
            A critical memory corruption has occurred. The system has been halted to prevent hardware damage.
            Please contact your administrator or perform a factory reset.
          </p>
          <div className="pt-8 border-t border-white/10">
             <p className="text-white/20 text-[10px]">Error Dump: CORE_ST_TRAP_ADDR_FAULT</p>
          </div>
        </div>
      </div>
    );
  }

  if (isCamouflaged) return <DecoyLayout />;

  const currentServer = servers.find(s => s.id === selectedServer);

  return (
    <div className="h-screen bg-background text-white font-sans flex flex-col overflow-hidden relative">
      <div className="ambient-bg" />
      
      <AnimatePresence mode="wait">
        {!isAuthenticated ? (
          <ActivationCard key="activation" onSuccess={handleActivationSuccess} initialToken={deepLinkToken || undefined} />
        ) : (
          <div className={`flex-1 flex flex-col h-full mx-auto w-full px-6 py-6 relative z-10 transition-all duration-500 ${isExpanded ? "max-w-none" : "max-w-[800px]"}`}>
            {/* Top App Bar */}
            <header className="flex justify-between items-center mb-8 px-2">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-[#0f0f0f] border border-white/5 flex items-center justify-center shadow-2xl transition-all duration-300 hover:border-primary/40">
                  <ShieldCheck size={24} className="text-primary" strokeWidth={1.5} />
                </div>
                <div className="flex flex-col">
                  <h1 className="text-lg font-black text-white tracking-tighter leading-none uppercase">
                    Shadow<span className="text-primary">Mesh</span>
                  </h1>
                  <div className="flex items-center gap-2 mt-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] animate-pulse" />
                    <span className="text-[9px] font-black text-text-secondary uppercase tracking-[0.25em] opacity-50">System Integrity Verified</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setIsLocked(true)}
                  data-testid="lock-button"
                  className="w-12 h-12 rounded-2xl bg-[#0f0f0f] text-text-secondary border border-white/5 hover:border-red-500/40 hover:text-red-400 transition-all duration-300 flex items-center justify-center"
                >
                  <Lock size={20} strokeWidth={1.5} />
                </button>
                <button
                  onClick={() => handleTabChange("settings")}
                  className={`w-12 h-12 rounded-2xl flex items-center justify-center transition-all duration-300 ${
                    dashTab === "settings"
                      ? "bg-primary text-white shadow-[0_0_30px_rgba(var(--primary-rgb),0.2)]"
                      : "bg-[#0f0f0f] text-text-secondary border border-white/5 hover:border-primary/40 hover:text-white"
                  }`}
                >
                  <User size={20} strokeWidth={1.5} />
                </button>
              </div>
            </header>

            {!integrityVerified && (
              <motion.div
                initial={{ opacity: 0, y: -20, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={SPRING_CONFIG}
                className="bg-amber-500/10 border border-amber-500/20 p-4 rounded-3xl mb-8 flex items-center gap-4"
              >
                <div className="bg-amber-500/20 p-2 rounded-xl">
                  <Lock className="text-amber-400" size={20} />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Integrity Warning</h3>
                  <p className="text-[10px] text-text-secondary font-medium">Core binary verification failed. Security may be compromised.</p>
                </div>
              </motion.div>
            )}

            {!daemonOnline && (
              <motion.div
                initial={{ opacity: 0, y: -20, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={SPRING_CONFIG}
                className="bg-red-500/10 border border-red-500/20 p-4 rounded-3xl mb-8 flex items-center gap-4"
              >
                <div className="bg-red-500/20 p-2 rounded-xl">
                  <ShieldOff className="text-red-400" size={20} />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">ShadowMesh Daemon Offline</h3>
                  <p className="text-[10px] text-text-secondary font-medium">Core service unreachable. VPN functionality disabled.</p>
                </div>
              </motion.div>
            )}

            <main className="flex-1 flex flex-row min-h-0 overflow-hidden gap-12 relative">
              {/* Left Panel - Hardware Accelerated */}
              <div
                className={`flex-shrink-0 flex flex-col h-full transition-all duration-500 ease-out will-change-transform transform-gpu ${
                  isExpanded
                    ? "w-[320px]"
                    : "w-full"
                } ${isResizing ? "pointer-events-none" : ""}`}
                style={{ transform: 'translateZ(0)' }}
              >
                <div className="flex-1 flex flex-col h-full overflow-hidden">
                  {dashTab === "features" ? (
                    <motion.div
                      key="features-tab"
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                      transition={SPRING_CONFIG}
                      className="flex-1 overflow-y-auto m3-scrollbar pr-1 pb-10"
                    >
                      {/* Technical Status Header */}
                      <div className="bg-surface/60 border border-white/[0.04] rounded-[32px] p-6 mb-8 relative overflow-hidden group shadow-xl backdrop-blur-xl">
                        <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-primary/[0.02] blur-[100px] rounded-full -mr-40 -mt-40 transition-all duration-1000 group-hover:bg-primary/[0.04]" />

                        <div className="flex items-center justify-between mb-8 relative z-10">
                          <div className="flex items-center gap-4">
                            <div className="w-11 h-11 rounded-2xl bg-white/[0.03] border border-white/[0.08] flex items-center justify-center shadow-xl transition-all duration-500 group-hover:border-primary/30">
                              <Shield size={20} className="text-primary/80" strokeWidth={1.5} />
                            </div>
                            <div>
                              <h2 className="text-sm font-black text-white tracking-widest uppercase leading-none">Security Core</h2>
                              <p className="text-[9px] font-mono text-text-secondary opacity-30 mt-1.5 uppercase tracking-tighter">V2.4.0-STABLE </p>
                            </div>
                          </div>
                          <div className="text-right">
                             <div className="flex items-center gap-3 justify-end">
                                <span className="text-[9px] font-black text-emerald-500 tracking-[0.2em] uppercase">Secure</span>
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)] animate-pulse" />
                             </div>
                             <p className="text-[8px] font-mono text-text-secondary mt-1 uppercase opacity-25 tracking-widest">Audit // 02</p>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-3 relative z-10">
                           <TechnicalStat label="INTEGRITY" value={integrityVerified ? "VERIFIED" : "FAIL"} status={integrityVerified ? "ok" : "err"} />
                           <TechnicalStat label="DAEMON" value={daemonOnline ? "RUNNING" : "OFFLINE"} status={daemonOnline ? "ok" : "err"} />
                        </div>
                      </div>

                      <div className="space-y-12">
                        <section>
                          <div className="flex items-center justify-between mb-8 px-2">
                            <div className="flex items-center gap-4">
                               <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                               <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Network Shield</h3>
                            </div>
                            <span className="text-[10px] font-mono text-text-secondary uppercase tracking-[0.3em] opacity-30">02 Active</span>
                          </div>
                          <div className="flex flex-col gap-3">
                            <SmartFallback />
                            <FeatureToggle
                              label="Network Kill Switch"
                              desc="Terminate traffic on tunnel failure"
                              enabled={killSwitch}
                              onToggle={handleKillSwitchToggle}
                            />
                            <FeatureToggle
                              label="Stealth Obfuscation"
                              desc="TLS 1.3 Traffic Masking // DPI Bypass"
                              enabled={obfuscation}
                              onToggle={handleObfuscationToggle}
                            />
                          </div>
                        </section>

                        <section>
                          <div className="flex items-center justify-between mb-8 px-2">
                            <div className="flex items-center gap-4">
                               <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                               <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Forensic Modules</h3>
                            </div>
                            <span className="text-[10px] font-mono text-text-secondary uppercase tracking-[0.3em] opacity-30">04 Ready</span>
                          </div>
                          <div className="flex flex-col gap-3">
                            <DeviceIdentity />
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              <DuressPinConfig />
                              <CamouflageSettings />
                            </div>
                            <PanicButton />
                          </div>
                        </section>

                        <section>
                           <div className="flex items-center justify-between mb-8 px-2">
                              <div className="flex items-center gap-4">
                                 <div className="w-1.5 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(var(--primary-rgb),0.6)]" />
                                 <h3 className="text-sm font-black text-text-primary uppercase tracking-[0.35em]">Audit Engine // Logs</h3>
                              </div>
                           </div>
                           <div className="flex flex-col gap-6">
                              <SecurityEventsList />
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                 <DiagnosticCard />
                                 <LogViewer />
                              </div>
                           </div>
                        </section>
                      </div>
                    </motion.div>
                  ) : dashTab === "settings" ? (
                    <motion.div
                      key="settings-tab"
                      initial={{ opacity: 0, x: 20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: -20 }}
                      transition={SPRING_CONFIG}
                      className="flex-1 overflow-y-auto m3-scrollbar pb-10 pr-2"
                    >
                      <AccountSettings onLogout={() => setIsAuthenticated(false)} />
                    </motion.div>
                  ) : (
                    <div
                      key="vpn-tab"
                      className="flex-1 flex flex-col h-full overflow-hidden"
                    >
                      {/* Status Card */}
                      <div className={`flex flex-col items-center transition-all duration-500 ${isExpanded ? "mb-2 scale-75" : "mb-6"}`}>
                         <StatusBadge
                          status={connStatus === "connected" ? "online" : connStatus === "error" ? "error" : connStatus === "disconnected" ? "offline" : "connecting"}
                          plan={plan}
                          label={
                            connStatus === "disconnected" ? "Not Connected" :
                            connStatus === "connected" ? (connStateLabel === "Connected" ? "Protected" : connStateLabel) :
                            connStatus === "error" ? "Connection Failed" : connStateLabel + "..."
                          }
                        />
                      </div>

                      {connStatus === "connected" && !isExpanded && (
                        <div className="mb-6">
                           <NetworkMonitor />
                        </div>
                      )}

                      {/* Central Button */}
                      <div className={`flex items-center justify-center transition-all duration-500 ${isExpanded ? "flex-none py-2" : "flex-1 py-4"}`}>
                        <div className="relative group">
                          <AnimatePresence>
                            {(connStatus !== "disconnected") && (
                              <>
                                <motion.div
                                  initial={{ scale: 0.8, opacity: 0.5 }}
                                  animate={{ scale: [1, 2], opacity: [0.5, 0] }}
                                  transition={{ repeat: Infinity, duration: 2.5, ease: "easeOut" }}
                                  className={`absolute inset-0 rounded-full blur-3xl ${
                                    connStatus === "connected" ? "bg-emerald-500/30" : "bg-primary/30"
                                  }`}
                                />
                                <motion.div
                                  initial={{ scale: 0.8, opacity: 0.3 }}
                                  animate={{ scale: [1, 2.5], opacity: [0.3, 0] }}
                                  transition={{ repeat: Infinity, duration: 3.5, ease: "easeOut", delay: 0.5 }}
                                  className={`absolute inset-0 rounded-full blur-[60px] ${
                                    connStatus === "connected" ? "bg-emerald-500/20" : "bg-primary/20"
                                  }`}
                                />
                              </>
                            )}
                          </AnimatePresence>

                          <motion.button
                            whileHover={{ scale: 1.05, translateY: -4 }}
                            whileTap={{ scale: 0.94 }}
                            onClick={toggleVPN}
                            data-testid="vpn-toggle-button"
                            className={`relative rounded-full flex flex-col items-center justify-center shadow-[0_40px_80px_rgba(0,0,0,0.5)] transition-all duration-700 transform-gpu ${
                              isExpanded ? "w-[160px] h-[160px] gap-1" : "w-[240px] h-[240px] gap-5"
                            } ${
                              connStatus === "connected"
                                ? "bg-gradient-to-br from-emerald-400 to-emerald-600 border border-emerald-300/30"
                                : "bg-gradient-to-br from-[#1e1e1e] to-[#0a0a0a] border border-white/10"
                            }`}
                          >
                            {/* Inner Glow/Shadow */}
                            <div className={`absolute inset-[10px] rounded-full border border-white/5 transition-all duration-700 ${
                               connStatus === "connected" ? "bg-emerald-400/20" : "bg-white/[0.02]"
                            }`} />

                            <div className={`relative z-10 p-6 rounded-full shadow-2xl backdrop-blur-md border transition-all duration-700 ${
                              connStatus === "connected"
                                ? "bg-white/20 border-white/40 text-white"
                                : "bg-primary/10 border-primary/20 text-primary shadow-[0_0_40px_rgba(var(--primary-rgb),0.2)]"
                            }`}>
                              {connStatus === "connected" ?
                                <Shield size={isExpanded ? 36 : 64} strokeWidth={1} className="drop-shadow-[0_0_15px_rgba(255,255,255,0.5)]" /> :
                                <Power size={isExpanded ? 36 : 64} strokeWidth={1} className="drop-shadow-[0_0_15px_rgba(var(--primary-rgb),0.5)]" />
                              }
                            </div>

                            <span className={`relative z-10 font-black tracking-[0.3em] uppercase text-[10px] transition-colors duration-700 ${
                              connStatus === "connected" ? "text-white" : "text-text-primary"
                            }`}>
                              {connStatus === "connected" ? "Protected" : "Connect"}
                            </span>

                            {/* Neon ring for inactive state */}
                            {connStatus === "disconnected" && (
                              <div className="absolute inset-0 rounded-full border-2 border-primary/20 animate-pulse" />
                            )}
                          </motion.button>
                        </div>
                      </div>

                      {/* Info Cards */}
                      <motion.div
                        whileHover={{ backgroundColor: "rgba(255,255,255,0.04)", y: -4 }}
                        onClick={() => handleTabChange("vpn", isExpanded)}
                        data-testid="active-gateway-card"
                        className={`relative overflow-hidden flex items-center justify-between transition-all duration-700 rounded-[32px] border ${
                          isExpanded
                            ? "p-4 mb-3 border-primary/20 bg-primary/5 cursor-default"
                            : "p-5 mb-4 cursor-pointer border-white/5 bg-white/[0.02] backdrop-blur-xl hover:border-primary/30"
                        }`}
                      >
                        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

                        <div className="relative z-10 flex items-center gap-4">
                          <div className={`flex items-center justify-center rounded-[22px] border border-white/10 shadow-inner group-hover:rotate-6 transition-transform duration-500 bg-white/[0.03] ${
                            isExpanded ? "w-10 h-10 text-xl" : "w-14 h-14 text-3xl"
                          }`}>
                            {currentServer?.flag || "🌐"}
                          </div>
                          <div>
                            <p className="text-[9px] text-text-muted font-black uppercase tracking-[0.25em] mb-0.5">Active Gateway</p>
                            <h3 className={`${isExpanded ? "text-sm" : "text-base"} font-bold text-text-primary tracking-tight`}>{currentServer?.name || "Global Auto-Route"}</h3>
                          </div>
                        </div>
                        {!isExpanded && (
                          <div className="relative z-10 p-3 rounded-2xl bg-white/[0.03] text-text-muted group-hover:text-primary group-hover:bg-primary/10 transition-all duration-500 border border-white/5 group-hover:border-primary/20">
                            <ChevronRight size={20} />
                          </div>
                        )}
                      </motion.div>

                      <div className={`grid gap-3 transition-all duration-500 ${isExpanded ? "grid-cols-1 mb-3" : "grid-cols-2 mb-2"}`}>
                         <StatCard
                          label="Download"
                          value={trafficStats ? `${(trafficStats.recv_bps / (1024 * 1024)).toFixed(1)} MB/s` : "0.0 KB/s"}
                          icon={<Zap size={14} />}
                          subValue="Encrypted"
                          testId="vpn-stat-download"
                        />
                        <StatCard
                          label="Upload"
                          value={trafficStats ? `${(trafficStats.sent_bps / (1024 * 1024)).toFixed(1)} MB/s` : "0.0 KB/s"}
                          icon={<Activity size={14} />}
                          color="#10b981"
                          subValue="Stable"
                          testId="vpn-stat-upload"
                        />
                      </div>

                      {isExpanded && (
                        <motion.div
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="mt-6 space-y-4"
                        >
                          <div className="flex items-center gap-2 px-2">
                            <Activity size={14} className="text-primary" />
                            <h3 className="text-[11px] font-bold text-text-secondary uppercase tracking-widest">Active Integrity</h3>
                          </div>
                          <div className="m3-card-tonal p-5 flex items-center justify-between border-primary/20 bg-primary/5 shadow-inner">
                            <div className="flex items-center gap-4">
                              <div className="p-2 rounded-xl bg-primary/20">
                                <ShieldCheck size={18} className="text-primary" />
                              </div>
                              <div>
                                <span className="text-sm font-bold text-text-primary block">Encryption Layer</span>
                                <span className="text-[10px] text-text-secondary font-medium">X25519 Verified</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                               <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                               <span className="text-[11px] font-bold text-emerald-500 uppercase tracking-tight">Active</span>
                            </div>
                          </div>
                        </motion.div>
                      )}

                      {connStatus === "connected" && !isExpanded && (
                        <ConnectionDetails stats={trafficStats} />
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Right Panel - Node Selection (Only visible in VPN tab) */}
              <AnimatePresence>
                {(isExpanded && dashTab === "vpn") && (
                  <motion.div
                    initial={{ opacity: 0, x: 30, scale: 0.98 }}
                    animate={{ opacity: 1, x: 0, scale: 1 }}
                    exit={{ opacity: 0, x: 30, scale: 0.98 }}
                    transition={SPRING_CONFIG}
                    className="flex-1 overflow-hidden flex flex-col border-l border-white/5 pl-8 will-change-transform"
                  >
                    <div className="flex justify-between items-end mb-10 px-2">
                      <div>
                        <h2 className="text-3xl font-bold text-white tracking-tight">Select Location</h2>
                        <p className="text-text-secondary mt-1 font-medium text-sm">Optimized for your current region</p>
                      </div>
                    </div>

                    <div className="flex-1 overflow-y-auto m3-scrollbar pr-2 pb-10" data-testid="server-list">
                      <div className="grid grid-cols-1 gap-4">
                        {servers.map((server) => {
                          const isActive = selectedServer === server.id;
                          return (
                            <motion.div
                              key={server.id}
                              data-testid={`server-node-${server.id}`}
                              whileHover={{ x: 6, backgroundColor: "rgba(255,255,255,0.04)" }}
                              whileTap={{ scale: 0.985 }}
                              onClick={() => {
                                setSelectedServer(server.id);
                                void updateWindowSize("vpn", true);
                              }}
                              className={`m3-card-tonal p-5 flex items-center justify-between cursor-pointer border transition-all duration-300 relative group overflow-hidden ${
                                isActive ? "border-primary/40 bg-primary/5 shadow-md" : "border-white/5 bg-surface hover:border-white/10"
                              }`}
                            >
                              {isActive && <div className="absolute top-0 left-0 w-1 h-full bg-primary" />}
                              <div className="flex items-center gap-5">
                                <div className="text-2xl filter drop-shadow-md group-hover:rotate-6 transition-transform duration-300">{server.flag}</div>
                                <div>
                                  <p className={`font-bold text-base tracking-tight transition-colors ${isActive ? "text-primary" : "text-text-primary"}`}>{server.name}</p>
                                  <div className="flex items-center gap-2 mt-0.5">
                                    <p className="text-[11px] text-text-secondary font-medium uppercase tracking-tight">{server.location}</p>
                                    {isActive && (
                                      <div className="flex items-center gap-1 bg-primary/10 px-1.5 py-0.5 rounded text-[9px] font-bold text-primary uppercase tracking-tighter">
                                        <Zap size={8} fill="currentColor" /> Best
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-center gap-4">
                                <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-[11px] font-bold font-mono border transition-colors ${
                                  server.ping < 50
                                    ? "bg-emerald-500/10 text-emerald-500 border-emerald-500/20"
                                    : server.ping === 0
                                      ? "bg-white/5 text-text-muted border-white/10"
                                      : "bg-amber-500/10 text-amber-500 border-amber-500/20"
                                }`}>
                                  <div className={`w-1.5 h-1.5 rounded-full ${server.ping < 50 ? "bg-emerald-500" : server.ping === 0 ? "bg-text-muted" : "bg-amber-500"}`} />
                                  {server.ping === 0 ? "--" : `${server.ping}ms`}
                                </div>
                                {isActive && (
                                  <motion.div
                                    initial={{ scale: 0 }}
                                    animate={{ scale: 1 }}
                                    className="w-5 h-5 rounded-full bg-primary/20 flex items-center justify-center border border-primary/30"
                                  >
                                    <div className="w-2 h-2 rounded-full bg-primary shadow-[0_0_8px_rgba(var(--primary-rgb),0.6)]" />
                                  </motion.div>
                                )}
                              </div>
                            </motion.div>
                          );
                        })}
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </main>

            {/* Navigation Bar */}
            <nav className="mt-4 bg-[#0f0f0f] rounded-3xl p-1.5 flex justify-around items-center border border-white/5 relative shadow-2xl overflow-hidden mb-2">
              {[
                { id: "vpn", icon: <Activity size={20} />, label: "VPN Tunnel" },
                { id: "features", icon: <LayoutGrid size={20} />, label: "Security" },
              ].map((item) => {
                const isActive = dashTab === item.id;
                return (
                  <button
                    key={item.id}
                    data-testid={`dash-tab-${item.id}`}
                    onClick={() => handleTabChange(item.id as DashTab)}
                    className="flex-1 relative flex flex-col items-center py-3 group outline-none transition-all duration-300"
                  >
                    <AnimatePresence>
                      {isActive && (
                        <motion.div
                          layoutId="nav-pill"
                          className="absolute inset-0 bg-white/[0.03] border border-white/5 rounded-2xl"
                          transition={{ type: "spring", stiffness: 400, damping: 30 }}
                        />
                      )}
                    </AnimatePresence>
                    <div className={`relative z-10 transition-all duration-300 mb-1 ${isActive ? "text-primary scale-110" : "text-text-muted group-hover:text-white"}`}>
                      {React.cloneElement(item.icon as React.ReactElement<{ strokeWidth?: number }>, { strokeWidth: 2 })}
                    </div>
                    <span className={`relative z-10 text-[9px] font-bold uppercase tracking-[0.2em] transition-all duration-300 ${isActive ? "text-white opacity-100" : "text-text-muted opacity-40 group-hover:opacity-70"}`}>
                      {item.label}
                    </span>
                  </button>
                );
              })}
            </nav>
          </div>
        )}
      </AnimatePresence>

      <LockScreen isLocked={isLocked} onUnlock={() => setIsLocked(false)} onDuress={handlePanicWipe} />
    </div>
  );
};



const TechnicalStat = ({ label, value, status }: { label: string; value: string; status: "ok" | "err" | "warn" }) => (
  <motion.div
    whileHover={{ scale: 1.02, backgroundColor: "rgba(255,255,255,0.06)" }}
    whileTap={{ scale: 0.98 }}
    className="bg-[#121212]/60 rounded-2xl p-4 border border-white/[0.04] flex flex-col justify-between transition-all duration-500 hover:bg-[#161616] group/stat cursor-default"
  >
    <div className="flex items-start justify-between">
      <span className="text-[8px] font-black text-text-secondary uppercase tracking-[0.2em] opacity-20 group-hover/stat:opacity-40 transition-opacity">{label}</span>
      <div className={`w-1.5 h-1.5 rounded-full mt-0.5 ${status === "ok" ? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.3)]" : "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.3)]"}`} />
    </div>
    <span className="text-sm font-black text-white tracking-widest uppercase font-mono group-hover/stat:text-primary transition-all duration-500 mt-2">
      {value}
    </span>
  </motion.div>
);

/* eslint-disable @typescript-eslint/no-unused-vars */
interface SummaryPillProps {
  active: boolean;
  label: string;
  icon: React.ReactNode;
}

const SummaryPill = ({ active, label, icon }: SummaryPillProps) => (
  <div className={`flex items-center gap-3 px-4 py-3 rounded-2xl border backdrop-blur-md transition-all duration-500 ${
    active
      ? "bg-emerald-500/5 border-emerald-500/10 text-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.05)]"
      : "bg-red-500/5 border-red-500/10 text-red-400 opacity-60"
  }`}>
    <div className={`p-1.5 rounded-xl transition-colors duration-500 ${active ? "bg-emerald-500/10" : "bg-red-500/10"}`}>
      {React.cloneElement(icon as React.ReactElement<{ size?: number; strokeWidth?: number }>, { size: 14, strokeWidth: 2.5 })}
    </div>
    <span className="text-[9px] font-black uppercase tracking-widest">{label}</span>
  </div>
);

export default App;
// Force trigger public export
