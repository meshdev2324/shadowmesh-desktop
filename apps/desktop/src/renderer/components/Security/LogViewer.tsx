import React, { useEffect, useState, useRef } from "react";
import { Terminal, Copy, Trash2, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const LogViewer: React.FC = () => {
  const [logs, setLogs] = useState<string[]>([]);
  const [isExpanded, setIsExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const getLogs = async () => {
    if (!window.electronAPI) return;
    setLoading(true);
    try {
       const data = await window.electronAPI.getLogs();
       setLogs(data || []);
    } catch (err) {
       console.error(err);
    } finally {
       setLoading(false);
    }
  };

  useEffect(() => {
    if (isExpanded) {
      void getLogs();
      const interval = setInterval(() => { void getLogs(); }, 5000);
      return () => clearInterval(interval);
    }
  }, [isExpanded]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="m3-card-tonal overflow-hidden flex flex-col transition-all duration-500 border border-white/5 bg-surface/30" style={{ height: isExpanded ? "400px" : "64px" }}>
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="flex items-center justify-between p-5 w-full hover:bg-white/5 transition-colors group"
      >
        <div className="flex items-center gap-4">
          <div className="p-2.5 rounded-xl bg-white/5 text-text-secondary border border-white/5 group-hover:border-primary/20 transition-colors">
            <Terminal size={18} />
          </div>
          <div className="text-left">
            <div className="font-bold text-text-primary tracking-tight">Real-time Logs</div>
            <div className="text-[11px] text-text-secondary font-medium">Core service debug output</div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {loading && <RefreshCw size={14} className="animate-spin text-primary opacity-50" />}
          <div className="p-1 rounded-lg bg-white/5 text-text-muted">
             {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </div>
        </div>
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex-1 flex flex-col min-h-0 bg-black/60 border-t border-white/5"
          >
            <div
              ref={scrollRef}
              className="flex-1 overflow-y-auto p-5 font-mono text-[11px] leading-relaxed m3-scrollbar selection:bg-primary/30"
            >
              {logs.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-text-muted italic gap-3">
                  <Terminal size={24} className="opacity-10" />
                  <p className="text-xs">Waiting for stream...</p>
                </div>
              ) : (
                logs.map((log, i) => {
                  const isError = log.includes("[ERROR]") || log.includes("Error") || log.includes("Failed");
                  const isWarn = log.includes("[WARN]") || log.includes("Warning");
                  return (
                    <div key={i} className={`mb-1.5 break-all font-medium ${isError ? "text-red-400" : isWarn ? "text-amber-400" : "text-text-secondary"}`}>
                      <span className="opacity-20 mr-3 select-none">{(i + 1).toString().padStart(3, '0')}</span>
                      {log}
                    </div>
                  );
                })
              )}
            </div>

            <div className="p-3 bg-black/40 border-t border-white/5 flex justify-end gap-3 px-5">
              <button
                onClick={() => {
                  void navigator.clipboard.writeText(logs.join("\n"));
                }}
                className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-white/5 hover:bg-white/10 text-text-secondary hover:text-text-primary transition-all text-[11px] font-bold"
              >
                <Copy size={14} />
                Copy
              </button>
              <button
                onClick={() => setLogs([])}
                className="p-1.5 rounded-xl hover:bg-red-500/10 text-text-muted hover:text-red-400 transition-all"
                title="Clear Logs"
              >
                <Trash2 size={16} />
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default LogViewer;
