import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import FeatureToggle from "../FeatureToggle";
import "@testing-library/jest-dom/vitest";

describe("FeatureToggle Component (Tactile Polish)", () => {
  it("renders correctly with label and description", () => {
    const onToggle = vi.fn();
    render(
      <FeatureToggle
        label="TEST_FEATURE"
        desc="TEST_DESCRIPTION"
        enabled={false}
        onToggle={onToggle}
      />
    );

    expect(screen.getByText("TEST_FEATURE")).toBeInTheDocument();
    expect(screen.getByText("TEST_DESCRIPTION")).toBeInTheDocument();
  });

  it("calls onToggle when clicked", () => {
    const onToggle = vi.fn();
    render(
      <FeatureToggle
        label="TEST_FEATURE"
        desc="TEST_DESCRIPTION"
        enabled={false}
        onToggle={onToggle}
      />
    );

    fireEvent.click(screen.getByText("TEST_FEATURE"));
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  it("applies correct visual state when enabled", () => {
    const { container } = render(
      <FeatureToggle
        label="TEST"
        desc="TEST"
        enabled={true}
        onToggle={() => {}}
      />
    );

    // Check for the primary background class when enabled
    const track = container.querySelector(".bg-primary");
    expect(track).toBeInTheDocument();
  });
});
