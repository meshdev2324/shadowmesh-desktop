import { sha256 } from "../renderer/services/powSolver";

// DH Parameters: 256-bit safe prime p and generator g = 2
const DH_P = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
const DH_G = BigInt(2);

export function generateDHPrivateKey(): bigint {
  const bytes = new Uint8Array(32);
  if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  let hex = "";
  bytes.forEach(b => hex += b.toString(16).padStart(2, "0"));
  return BigInt("0x" + hex) % DH_P;
}

export function computeDHPublicKey(privateKey: bigint): bigint {
  return modExp(DH_G, privateKey, DH_P);
}

export function computeDHSharedSecret(privateKey: bigint, otherPublicKey: bigint): bigint {
  return modExp(otherPublicKey, privateKey, DH_P);
}

function modExp(base: bigint, exp: bigint, mod: bigint): bigint {
  let res = BigInt(1);
  base = base % mod;
  let e = exp;
  while (e > BigInt(0)) {
    if (e % BigInt(2) === BigInt(1)) {
      res = (res * base) % mod;
    }
    base = (base * base) % mod;
    e = e / BigInt(2);
  }
  return res;
}

export function bigIntToHex64(val: bigint): string {
  return val.toString(16).padStart(64, "0");
}

interface SessionPollResponse {
  status: string;
  mobile_public_key?: string;
}

function parseSessionPollResponse(data: unknown): SessionPollResponse | null {
  if (typeof data !== "object" || data === null) {
    return null;
  }
  const record = data as Record<string, unknown>;
  if (typeof record.status !== "string") {
    return null;
  }
  const mobilePublicKey =
    typeof record.mobile_public_key === "string"
      ? record.mobile_public_key
      : undefined;
  return { status: record.status, mobile_public_key: mobilePublicKey };
}

export function encryptPayload(plaintext: string, pin: string): string {
  const pinHash = sha256(pin);
  const bytes = new TextEncoder().encode(plaintext);
  const encryptedBytes = new Uint8Array(bytes.length);
  
  for (let i = 0; i < bytes.length; i++) {
    const keyByteHex = sha256(`${pinHash}-${i}`).substring(0, 2);
    const keyByte = parseInt(keyByteHex, 16);
    encryptedBytes[i] = bytes[i] ^ keyByte;
  }
  
  let hex = "";
  encryptedBytes.forEach(b => hex += b.toString(16).padStart(2, "0"));
  return hex;
}

export function decryptPayload(ciphertextHex: string, pin: string): string {
  const pinHash = sha256(pin);
  const len = ciphertextHex.length / 2;
  const decryptedBytes = new Uint8Array(len);
  
  for (let i = 0; i < len; i++) {
    const hexPart = ciphertextHex.substring(i * 2, i * 2 + 2);
    const byteVal = parseInt(hexPart, 16);
    const keyByteHex = sha256(`${pinHash}-${i}`).substring(0, 2);
    const keyByte = parseInt(keyByteHex, 16);
    decryptedBytes[i] = byteVal ^ keyByte;
  }
  
  return new TextDecoder().decode(decryptedBytes);
}

export const SessionManager = {
  // Generate random 6-digit PIN
  generatePairingPIN(): string {
    let pin = "";
    for (let i = 0; i < 6; i++) {
      pin += Math.floor(Math.random() * 10).toString();
    }
    return pin;
  },

  // Generate random handshake secret (32 chars hex)
  generateHandshakeSecret(): string {
    const bytes = new Uint8Array(16);
    if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  },

  // Initiate the pairing sequence with the server
  async initiatePairing(apiBaseUrl: string) {
    const pin = this.generatePairingPIN();
    const handshakeSecret = this.generateHandshakeSecret();
    const privateKey = generateDHPrivateKey();
    const publicKey = computeDHPublicKey(privateKey);
    const publicKeyHex = bigIntToHex64(publicKey);

    // Register with server
    const response = await fetch(`${apiBaseUrl}/api/v1/sessions/initiate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        handshake_secret: handshakeSecret,
        desktop_public_key: publicKeyHex,
      }),
    });

    if (!response.ok) {
      throw new Error("Failed to initiate pairing handshake with server");
    }

    // Encrypt QR Payload containing Server URL and temporary Handshake Secret
    const qrPayload = JSON.stringify({
      server_url: apiBaseUrl,
      handshake_secret: handshakeSecret,
      desktop_public_key: publicKeyHex,
    });

    const encryptedPayloadHex = encryptPayload(qrPayload, pin);

    return {
      pin,
      handshakeSecret,
      privateKey,
      publicKeyHex,
      encryptedPayload: encryptedPayloadHex,
    };
  },

  // Poll pairing status and complete key exchange
  pollAndRegister(
    apiBaseUrl: string,
    handshakeSecret: string,
    desktopPrivateKey: bigint,
    onSuccess: (sessionId: string, sessionToken: string) => void
  ) {
    const maxRetries = 24; // 2 minutes with 5s polling intervals
    let retries = 0;

    const poll = async () => {
      if (retries >= maxRetries) {
        throw new Error("Pairing timeout");
      }

      try {
        const response = await fetch(`${apiBaseUrl}/api/v1/sessions/poll/${handshakeSecret}`);
        if (!response.ok) {
          throw new Error("Handshake expired or deleted");
        }

        const data = parseSessionPollResponse(await response.json());
        if (data?.status === "paired" && data.mobile_public_key) {
          // Compute Diffie-Hellman Shared Secret
          const mobilePubKeyBigInt = BigInt(`0x${data.mobile_public_key}`);
          const sharedSecret = computeDHSharedSecret(desktopPrivateKey, mobilePubKeyBigInt);
          const sharedSecretHex = bigIntToHex64(sharedSecret);

          // Derive device-specific session token: SHA256 of the shared secret
          const sessionToken = sha256(sharedSecretHex);
          const sessionTokenHash = sha256(sessionToken); // Hash of token to store in memory safely
          const sessionId = `sess-${handshakeSecret.substring(0, 8)}`;

          // Register active session on server
          const regResponse = await fetch(`${apiBaseUrl}/api/v1/sessions/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              handshake_secret: handshakeSecret,
              session_id: sessionId,
              token_hash: sessionTokenHash,
            }),
          });

          if (!regResponse.ok) {
            throw new Error("Failed to register session token on server");
          }

          onSuccess(sessionId, sessionToken);
          return;
        }
      } catch (err) {
        console.error("Polling error:", err);
      }

      retries++;
      setTimeout(poll, 5000);
    };

    setTimeout(poll, 5000);
  },

  // Kill-Switch session revocation
  async revokeSession(apiBaseUrl: string, sessionId: string): Promise<boolean> {
    const response = await fetch(`${apiBaseUrl}/api/v1/sessions/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    });
    return response.ok;
  }
};
