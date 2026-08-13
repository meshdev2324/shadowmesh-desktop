import React, { useEffect, useState } from "react";
import { ShieldAlert, ShieldCheck, Clock } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { SecurityEvent } from "../../../types/shadowmesh-api";

const SecurityEventsList: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchEvents = async () => {
    if (window.electronAPI) {
      try {
        const data = await window.electronAPI.getSecurityEvents();
        if (Array.isArray(data)) {
          // Sort by timestamp descending
          const sorted = [...data].sort((a, b) => b.timestamp - a.timestamp);
          setEvents(sorted);
        } else {
          setEvents([]);
        }
      } catch (err) {
        console.error("Failed to fetch security events", err);
        setEvents([]);
      } finally {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    void fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="m3-card-tonal p-6 flex flex-col items-center justify-center gap-4">
        <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />
        <span className="text-xs font-semibold text-text-secondary">Verifying Security Log...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <AnimatePresence initial={false}>
        {events.length === 0 ? (
          <div className="m3-card-tonal p-10 text-center border-dashed border-white/5 bg-transparent">
             <ShieldCheck size={32} className="mx-auto text-emerald-500/20 mb-4" />
             <p className="text-sm text-text-secondary">No security threats detected in current session.</p>
          </div>
        ) : (
          events.slice(0, 5).map((event, idx) => (
            <motion.div
              key={`${event.timestamp}-${idx}`}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="m3-card-tonal p-5 flex items-start gap-4 hover:bg-surface transition-all duration-300 group border border-white/5 shadow-sm"
            >
              <div className={`p-3 rounded-2xl ${
                !event.success ? "bg-red-500/10 text-red-400" : "bg-emerald-500/10 text-emerald-400"
              }`}>
                {!event.success ? <ShieldAlert size={18} strokeWidth={2} /> : <ShieldCheck size={18} strokeWidth={2} />}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex justify-between items-center mb-1.5">
                  <span className="font-bold text-text-primary text-sm tracking-tight truncate pr-2">
                    {(event.event_type || 'Unknown').replace(/([A-Z])/g, ' $1').trim()}
                  </span>
                  <div className="flex items-center gap-1.5 text-text-muted whitespace-nowrap">
                    <Clock size={12} />
                    <span className="text-[11px] font-medium">
                      {new Date(event.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed line-clamp-2">
                  {event.details}
                </p>
              </div>
            </motion.div>
          ))
        )}
      </AnimatePresence>

      {events.length > 5 && (
        <button className="w-full py-3 text-xs font-bold text-primary hover:bg-primary/5 rounded-2xl transition-all border border-primary/10">
          View Full Audit Log
        </button>
      )}
    </div>
  );
};

export default SecurityEventsList;
