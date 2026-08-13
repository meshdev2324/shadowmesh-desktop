import React, { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { SessionManager } from "../../../main/session_manager";

interface ActiveSessionInfo {
  id: string;
  createdAt: string;
}

const API_BASE_URL =
  import.meta.env.VITE_API_URL ?? "http://localhost:8080";

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  if (typeof err === "string") {
    return err;
  }
  return "Failed to initiate secure pairing.";
}

export const QRGenerator: React.FC = () => {
  const [pin, setPin] = useState<string>("");
  const [encryptedPayload, setEncryptedPayload] = useState<string>("");
  const [status, setStatus] = useState<
    "idle" | "generating" | "waiting" | "pairing" | "completed" | "error"
  >("idle");
  const [activeSessions, setActiveSessions] = useState<ActiveSessionInfo[]>([]);
  const [errorMsg, setErrorMsg] = useState<string>("");

  const startPairingFlow = async () => {
    try {
      setStatus("generating");
      setErrorMsg("");

      const sessionData = await SessionManager.initiatePairing(API_BASE_URL);

      setPin(sessionData.pin);
      setEncryptedPayload(sessionData.encryptedPayload);
      setStatus("waiting");

      SessionManager.pollAndRegister(
        API_BASE_URL,
        sessionData.handshakeSecret,
        sessionData.privateKey,
        (sessionId, sessionToken) => {
          setStatus("completed");
          localStorage.setItem(`shadow_session_${sessionId}`, sessionToken);
          setActiveSessions((prev) => [
            ...prev,
            { id: sessionId, createdAt: new Date().toLocaleTimeString() },
          ]);
        },
      );
    } catch (err: unknown) {
      console.error(err);
      setStatus("error");
      setErrorMsg(getErrorMessage(err));
    }
  };

  const handleRevoke = async (sessionId: string) => {
    try {
      const success = await SessionManager.revokeSession(API_BASE_URL, sessionId);
      if (success) {
        setActiveSessions((prev) => prev.filter((s) => s.id !== sessionId));
        localStorage.removeItem(`shadow_session_${sessionId}`);
      }
    } catch (err: unknown) {
      console.error("Failed to revoke session:", err);
    }
  };

  useEffect(() => {
    void startPairingFlow();
  }, []);

  return (
    <div className="flex flex-col items-center justify-center p-6 bg-[#161821] border border-white/10 rounded-2xl shadow-xl w-full max-w-md mx-auto text-white">
      <div className="flex items-center space-x-2 mb-4">
        <span className="text-xl">🛡️</span>
        <h2 className="text-lg font-bold tracking-wide uppercase text-indigo-400">
          Device Pairing
        </h2>
      </div>

      {status === "generating" && (
        <div className="flex flex-col items-center py-10 space-y-4">
          <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-sm text-gray-400">Generating secure DH keypair...</p>
        </div>
      )}

      {status === "error" && (
        <div className="text-center py-6">
          <p className="text-red-500 font-semibold mb-3">⚠️ {errorMsg}</p>
          <button
            type="button"
            onClick={() => void startPairingFlow()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 transition rounded-lg text-sm font-medium"
          >
            Retry Pairing
          </button>
        </div>
      )}

      {(status === "waiting" || status === "pairing") && (
        <div className="flex flex-col items-center w-full space-y-6">
          <p className="text-xs text-gray-400 text-center px-4 leading-relaxed">
            Scan this QR code with your ShadowMesh Mobile scanner, then enter the
            6-digit secure pairing PIN shown below.
          </p>

          <div className="p-4 bg-white rounded-xl shadow-inner animate-pulse duration-1000">
            <QRCodeSVG value={encryptedPayload} size={180} />
          </div>

          <div className="flex flex-col items-center space-y-1">
            <span className="text-xs text-gray-500 uppercase tracking-widest">
              Pairing PIN
            </span>
            <span className="text-3xl font-extrabold tracking-widest text-indigo-300 font-mono bg-black/40 px-6 py-2 rounded-lg border border-indigo-500/20 shadow-md">
              {pin}
            </span>
          </div>

          <div className="flex items-center space-x-2 text-xs text-gray-500 animate-pulse">
            <span className="w-2 h-2 bg-green-500 rounded-full" />
            <span>Awaiting out-of-band mobile verification...</span>
          </div>
        </div>
      )}

      {status === "completed" && (
        <div className="flex flex-col items-center py-8 space-y-4 text-center">
          <div className="w-12 h-12 bg-green-500/10 border border-green-500/20 text-green-400 rounded-full flex items-center justify-center text-xl animate-bounce">
            ✓
          </div>
          <div>
            <h3 className="font-bold text-green-400">Device Authorized</h3>
            <p className="text-xs text-gray-400 mt-1">
              Diffie-Hellman exchange completed. Stateless session registered.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void startPairingFlow()}
            className="px-4 py-1.5 bg-indigo-600/30 hover:bg-indigo-600/50 transition border border-indigo-500/20 rounded-lg text-xs font-medium mt-2"
          >
            Pair Another Device
          </button>
        </div>
      )}

      {activeSessions.length > 0 && (
        <div className="w-full mt-6 pt-6 border-t border-white/5 space-y-3">
          <div className="flex justify-between items-center">
            <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Active Paired Devices
            </span>
            <span className="text-xs text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded">
              {activeSessions.length}
            </span>
          </div>

          <div className="space-y-2 max-h-32 overflow-y-auto">
            {activeSessions.map((session) => (
              <div
                key={session.id}
                className="flex items-center justify-between p-2.5 bg-black/25 border border-white/5 rounded-xl text-xs"
              >
                <div className="flex flex-col">
                  <span className="font-mono text-gray-300 font-semibold">
                    {session.id}
                  </span>
                  <span className="text-[10px] text-gray-500">
                    Paired at {session.createdAt}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => void handleRevoke(session.id)}
                  className="px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 hover:border-red-500/30 text-red-400 rounded-lg font-medium transition active:scale-95"
                >
                  Kill Switch
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

