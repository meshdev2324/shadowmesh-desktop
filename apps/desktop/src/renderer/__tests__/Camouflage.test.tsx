import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, beforeEach } from "vitest";
import App from "../App";
import { createTestElectronAPI } from "./testElectronAPI";
import React from "react";

describe("🧥 Camouflage Mode (Forensic Resistance)", () => {
  let camouflageCallback: ((enabled: boolean) => void) | undefined;

  beforeEach(() => {
    camouflageCallback = undefined;
    window.electronAPI = createTestElectronAPI({
      onCamouflageToggled: (callback) => {
        camouflageCallback = callback;
      },
    });
  });

  it("mounts DecoyLayout (Calculator) when camouflage is active", () => {
    render(<App />);

    expect(screen.queryByText("Calculator")).not.toBeInTheDocument();
    expect(camouflageCallback).toBeTypeOf("function");

    act(() => {
      camouflageCallback?.(true);
    });

    expect(screen.getByText("Calculator")).toBeInTheDocument();
    expect(screen.queryByText("ShadowMesh")).not.toBeInTheDocument();
  });
});
