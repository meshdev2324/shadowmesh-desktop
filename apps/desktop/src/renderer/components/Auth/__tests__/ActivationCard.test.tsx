import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import ActivationCard from "../ActivationCard";
import "@testing-library/jest-dom/vitest";

// Mock logo since it's an asset
vi.mock("@/assets/logo.png", () => ({ default: "mock-logo" }));

describe("ActivationCard (Polish & Formatting)", () => {
  it("formats the activation code with dashes automatically", () => {
    render(<ActivationCard onSuccess={() => {}} />);

    const input = screen.getByPlaceholderText(/XXXX-XXXX/i);
    if (!(input instanceof HTMLInputElement)) throw new Error("Not an input");

    // Type 10 chars
    fireEvent.change(input, { target: { value: "abcde12345" } });

    // Should format as XXXXX-XXXXX
    expect(input.value).toBe("ABCDE-12345");
  });

  it("handles backspacing correctly in formatted input", () => {
    render(<ActivationCard onSuccess={() => {}} />);
    const input = screen.getByPlaceholderText(/XXXX-XXXX/i);
    if (!(input instanceof HTMLInputElement)) throw new Error("Not an input");

    fireEvent.change(input, { target: { value: "ABCDE1" } });
    expect(input.value).toBe("ABCDE-1");

    fireEvent.change(input, { target: { value: "ABCDE" } });
    expect(input.value).toBe("ABCDE");
  });

  it("limits the code to 29 characters (5 segments of 5 + 4 dashes)", () => {
    render(<ActivationCard onSuccess={() => {}} />);
    const input = screen.getByPlaceholderText(/XXXX-XXXX/i);
    if (!(input instanceof HTMLInputElement)) throw new Error("Not an input");

    // Type 30 chars
    const longInput = "A".repeat(30);
    fireEvent.change(input, { target: { value: longInput } });

    expect(input.value.length).toBe(29);
  });
});
