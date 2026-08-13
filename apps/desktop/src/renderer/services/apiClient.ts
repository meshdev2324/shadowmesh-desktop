import axios, { InternalAxiosRequestConfig } from "axios";
import axiosRetry from "axios-retry";
import { PoWSolver, PoWChallenge, sha256 } from "./powSolver";


// In production, change this to your secure HTTPS endpoint
const envConfig = (import.meta as unknown as { env?: Record<string, string> })
  .env;

// Force HTTPS in production
const isProduction = process.env.NODE_ENV === "production";
let BASE_URL = envConfig?.VITE_API_URL || "http://localhost:8080";
if (isProduction && BASE_URL.startsWith("http://")) {
  BASE_URL = BASE_URL.replace("http://", "https://");
}

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15000, // Increased timeout for better stability
  headers: {
    "Content-Type": "application/json",
  },
});

// Configure robust retry logic
axiosRetry(api, {
  retries: 3,
  retryDelay: (retryCount) => {
    return retryCount * 1000; // Exponential backoff (1s, 2s, 3s)
  },
  retryCondition: (error) => {
    // Retry on network errors and 5xx responses
    return (
      axiosRetry.isNetworkOrIdempotentRequestError(error) ||
      (error.response?.status ? error.response.status >= 500 : false)
    );
  },
});

// Privacy-Safe Device Entropy
let cachedDeviceID: string | null = null;

const getRotatedDeviceID = async () => {
  if (cachedDeviceID) return cachedDeviceID;

  const electronAPI = window.electronAPI;
  let rawID = navigator.userAgent;

  if (electronAPI && typeof electronAPI.getMachineId === "function") {
    try {
      rawID = await electronAPI.getMachineId();
    } catch (e) {
      console.warn("Failed to get machine ID, falling back to user agent", e);
    }
  }

  const dailySalt = new Date().toISOString().split("T")[0];
  cachedDeviceID = sha256(rawID + dailySalt);
  return cachedDeviceID;
};

// Request Interceptor
api.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    console.info(
      `📡 ShadowMesh API: [${config.method?.toUpperCase()}] ${config.url}`,
    );

    const authToken = window.electronAPI
      ? await window.electronAPI.getSecureToken("vpn_desktop_token")
      : null;

    if (authToken) {
      config.headers.Authorization = `Bearer ${authToken}`;
    }

    config.headers["X-Shadow-Device-ID"] = await getRotatedDeviceID();
    return config;
  },
  (error: unknown) => {
    return Promise.reject(error instanceof Error ? error : new Error(String(error)));
  },
);

// Response Interceptor (Adaptive Friction / PoW)
api.interceptors.response.use(
  (response) => {
    console.info(
      `✅ ShadowMesh API: Success [${response.status}] ${response.config.url}`,
    );
    return response;
  },
  async (error: unknown) => {
    if (!axios.isAxiosError(error)) {
      return Promise.reject(error instanceof Error ? error : new Error(String(error)));
    }

    const originalRequest = error.config as
      | (InternalAxiosRequestConfig & { _retry?: boolean })
      | undefined;

    if (error.response?.status === 401) {
      if (window.electronAPI) {
        await window.electronAPI.removeSecureToken("vpn_desktop_token");
      }
      return Promise.reject(error);
    }

    // Handle Adaptive Friction (429 with PoW Challenge)
    if (
      originalRequest &&
      error.response?.status === 429 &&
      (error.response.data as { challenge?: PoWChallenge })?.challenge &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true;
      const challenge = (error.response.data as { challenge: PoWChallenge })
        .challenge;

      try {
        const solution = await PoWSolver.solve(challenge);

        // Attach solution headers
        originalRequest.headers["X-Shadow-PoW-Solution"] = solution.solution;
        originalRequest.headers["X-Shadow-PoW-Nonce"] = solution.nonce;
        originalRequest.headers["X-Shadow-PoW-Timestamp"] =
          solution.timestamp.toString();
        originalRequest.headers["X-Shadow-PoW-Signature"] = solution.signature;

        // Retry the original request
        return api(originalRequest);
      } catch (solveError) {
        console.error(
          "❌ ShadowMesh: Failed to solve PoW challenge",
          solveError,
        );
        return Promise.reject(error);
      }
    }

    return Promise.reject(error);
  },
);

export default api;
