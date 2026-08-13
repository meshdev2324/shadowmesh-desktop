import { sha256 as jsSha256 } from "js-sha256";

export function sha256(ascii: string): string {
  return jsSha256(ascii);
}

export interface PoWChallenge {
  nonce: string;
  difficulty: number;
  timestamp: number;
  signature: string;
}

export interface PoWSolution {
  solution: string;
  nonce: string;
  timestamp: number;
  signature: string;
}

export class PoWSolver {
  static async solve(challenge: PoWChallenge): Promise<PoWSolution> {
    const { nonce, difficulty, timestamp, signature } = challenge;
    const target = BigInt(1) << BigInt(256 - difficulty);

    let solution = 0;
    let hashInt = BigInt(0);

    console.log(
      `🛡️ ShadowMesh: Solving PoW Challenge (Diff: ${difficulty})...`,
    );
    const start = Date.now();

    while (true) {
      const data = `${nonce}${solution}`;
      const hashHex = sha256(data);
      hashInt = BigInt(`0x${hashHex}`);

      if (hashInt < target) {
        break;
      }

      solution++;

      if (solution % 1000 === 0) {
        // Yield to event loop to prevent UI freezing
        await new Promise((resolve) => setTimeout(resolve, 0));
      }

      if (Date.now() - start > 30000) {
        throw new Error("PoW solving timed out");
      }
    }

    const duration = Date.now() - start;
    console.log(
      `✅ ShadowMesh: PoW Solved in ${duration}ms (Solution: ${solution})`,
    );

    return {
      solution: solution.toString(),
      nonce,
      timestamp,
      signature,
    };
  }
}
