import React, { useState, useEffect } from "react";
import { Smartphone, Check, Edit2 } from "lucide-react";

import { VPNStatus } from "../../../types/shadowmesh-api";

const DeviceIdentity: React.FC = () => {
  const [deviceId, setDeviceId] = useState("Loading...");
  const [label, setLabel] = useState("");
  const [plan, setPlan] = useState("");
  const [isEditing, setIsEditing] = useState(false);
  const [tempLabel, setTempLabel] = useState("");

  useEffect(() => {
    if (window.electronAPI) {
      void window.electronAPI.getMachineId().then(setDeviceId);
      void window.electronAPI.getVPNStatus().then((status: VPNStatus) => {
         if (status.device_label) {
            setLabel(status.device_label);
            setTempLabel(status.device_label);
         }
         if (status.plan) {
            setPlan(status.plan);
         }
      });
    }
  }, []);

  const saveLabel = async () => {
    if (window.electronAPI && window.electronAPI.run_helper) {
      await window.electronAPI.run_helper({ args: ["set-label", tempLabel] });
      setLabel(tempLabel);
      setIsEditing(false);
    }
  };

  return (
    <div className="group space-y-2">
      <div className="flex items-center justify-between p-4 rounded-2xl hover:bg-white/[0.04] transition-all duration-300 border border-transparent hover:border-white/5">
        <div className="flex items-center gap-4">
          <div className="p-2.5 rounded-xl text-emerald-400 bg-emerald-400/10">
            <Smartphone size={20} strokeWidth={1.5} />
          </div>
          <div>
            <div className="text-sm font-bold text-white tracking-tight">Device Identity</div>
            <div className="flex items-center gap-2 mt-1">
              <div className="text-[10px] text-white/30 font-medium truncate max-w-[140px]">
                {label || "Hardware Fingerprint"}
              </div>
              {plan && (
                <div className="px-1.5 py-0.5 rounded-md bg-primary/10 border border-primary/20 text-[8px] font-black text-primary uppercase tracking-tighter">
                  {plan}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="flex gap-2">
           {isEditing ? (
             <div className="flex items-center gap-1">
                <input
                  type="text"
                  value={tempLabel}
                  onChange={(e) => setTempLabel(e.target.value)}
                  className="bg-black/40 border border-primary/50 rounded-lg px-2 py-1 text-[10px] text-white focus:outline-none w-24"
                  autoFocus
                  onKeyDown={(e) => e.key === "Enter" && saveLabel()}
                />
                <button onClick={saveLabel} className="p-1 text-primary">
                  <Check size={14} />
                </button>
             </div>
           ) : (
             <button
               onClick={() => setIsEditing(true)}
               className="p-2 text-white/20 hover:text-white transition-colors"
             >
               <Edit2 size={14} />
             </button>
           )}
        </div>
      </div>

      <div className="px-4 pb-2 space-y-3">
        <div className="bg-white/[0.02] border border-white/5 p-3 rounded-2xl">
          <div className="flex justify-between items-center mb-1">
             <span className="text-[8px] font-black text-white/20 uppercase tracking-[0.2em]">Hardware UUID</span>
             <span className="text-[8px] font-black text-emerald-500/40 uppercase tracking-widest">Verified</span>
          </div>
          <p className="text-[9px] font-mono text-white/40 break-all select-all cursor-copy">
            {deviceId}
          </p>
        </div>
      </div>
    </div>
  );
};

export default DeviceIdentity;
