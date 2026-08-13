import { describe, it, expect } from "vitest";
import { PoWSolver, sha256, type PoWChallenge } from "../services/powSolver";

describe("PoWSolver & SHA256", () => {
  it("generates correct SHA256 hashes", () => {
    // Standard test cases for SHA256
    expect(sha256("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(sha256("ShadowMesh")).toBe(
      "a49a6e17db242d84d6ea3ab63b03ffb727c5becae88211e03614a588f8492c0c",
    );
    // Let's use a known one: sha256("abc")
    expect(sha256("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("successfully solves a low difficulty PoW challenge", async () => {
    const challenge: PoWChallenge = {
      nonce: "test-nonce",
      difficulty: 8, // Very low difficulty for fast testing
      timestamp: Date.now(),
      signature: "mock-sig",
    };

    const solution = await PoWSolver.solve(challenge);

    expect(solution.nonce).toBe(challenge.nonce);
    expect(solution.timestamp).toBe(challenge.timestamp);
    expect(solution.signature).toBe(challenge.signature);
    expect(solution).toHaveProperty("solution");

    // Verify the solution
    const data = `${challenge.nonce}${solution.solution}`;
    const hashHex = sha256(data);
    const hashInt = BigInt(`0x${hashHex}`);
    const target = BigInt(1) << BigInt(256 - challenge.difficulty);

    expect(hashInt).toBeLessThan(target);
  });
});
