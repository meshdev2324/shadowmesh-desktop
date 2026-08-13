import React, { useState } from "react";
import { Share2, Plus, X, AppWindow } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const SplitTunnelSettings: React.FC = () => {
  const [enabled, setEnabled] = useState(false);
  const [mode, setMode] = useState<"include" | "exclude">("exclude");
  const [appList, setAppList] = useState<string[]>([]);
  const [newApp, setNewApp] = useState("");

  const updateConfig = async (newEnabled: boolean, newMode: "include" | "exclude", newList: string[]) => {
    if (!window.electronAPI) return;
    await window.electronAPI.setSplitTunnel({
      enabled: newEnabled,
      mode: newMode,
      apps: newList
    });
  };

  const handleToggle = () => {
    const next = !enabled;
    setEnabled(next);
    void updateConfig(next, mode, appList);
  };

  const addApp = () => {
    if (newApp.trim() && !appList.includes(newApp.trim())) {
      const newList = [...appList, newApp.trim()];
      setAppList(newList);
      setNewApp("");
      void updateConfig(enabled, mode, newList);
    }
  };

  const removeApp = (app: string) => {
    const newList = appList.filter(a => a !== app);
    setAppList(newList);
    void updateConfig(enabled, mode, newList);
  };

  return (
    <div className="m3-card-tonal p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-2xl transition-colors ${enabled ? "bg-indigo-500/20 text-indigo-400" : "bg-white/5 text-text-muted"}`}>
            <Share2 size={22} />
          </div>
          <div>
            <div className="font-bold text-white">Split Tunneling</div>
            <div className="text-xs text-text-secondary">Route specific apps only</div>
          </div>
        </div>
        <button
          onClick={handleToggle}
          className={`w-12 h-6 rounded-full relative transition-all duration-500 flex items-center px-1 ${
            enabled ? "bg-indigo-500" : "bg-white/10"
          }`}
        >
          <motion.div
            animate={{ x: enabled ? 24 : 0 }}
            transition={{ type: "spring", stiffness: 500, damping: 30 }}
            className="w-4 h-4 rounded-full bg-white shadow-sm"
          />
        </button>
      </div>

      <AnimatePresence>
        {enabled && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="space-y-4 pt-4 border-t border-white/5 overflow-hidden"
          >
            <div className="flex p-1 bg-black/20 rounded-xl border border-white/5">
              <button
                onClick={() => { setMode("exclude"); void updateConfig(enabled, "exclude", appList); }}
                className={`flex-1 py-1.5 text-[10px] font-black uppercase tracking-widest rounded-lg transition-all ${
                  mode === "exclude" ? "bg-white/10 text-white" : "text-text-muted hover:text-white"
                }`}
              >
                Exclude
              </button>
              <button
                onClick={() => { setMode("include"); void updateConfig(enabled, "include", appList); }}
                className={`flex-1 py-1.5 text-[10px] font-black uppercase tracking-widest rounded-lg transition-all ${
                  mode === "include" ? "bg-white/10 text-white" : "text-text-muted hover:text-white"
                }`}
              >
                Include
              </button>
            </div>

            <div className="space-y-2">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newApp}
                  onChange={(e) => setNewApp(e.target.value)}
                  placeholder="App executable name (e.g. chrome)"
                  className="flex-1 bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors"
                  onKeyDown={(e) => e.key === "Enter" && addApp()}
                />
                <button
                  onClick={addApp}
                  className="p-2 bg-indigo-500 text-white rounded-xl hover:bg-indigo-600 transition-colors"
                >
                  <Plus size={18} />
                </button>
              </div>

              <div className="flex flex-wrap gap-2">
                {appList.map((app) => (
                  <motion.div
                    key={app}
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    className="flex items-center gap-2 bg-white/5 border border-white/10 px-3 py-1.5 rounded-lg group"
                  >
                    <AppWindow size={12} className="text-text-muted" />
                    <span className="text-[10px] font-bold text-white">{app}</span>
                    <button onClick={() => removeApp(app)} className="text-text-muted hover:text-red-400 transition-colors">
                      <X size={12} />
                    </button>
                  </motion.div>
                ))}
                {appList.length === 0 && (
                  <p className="text-[10px] text-text-muted italic py-2">No apps added yet.</p>
                )}
              </div>
            </div>

            <p className="text-[9px] text-text-muted leading-relaxed bg-indigo-500/5 p-3 rounded-xl border border-indigo-500/10">
              <span className="text-indigo-400 font-bold uppercase mr-1">Pro Tip:</span>
              Use the executable name as it appears in the system process list.
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default SplitTunnelSettings;
