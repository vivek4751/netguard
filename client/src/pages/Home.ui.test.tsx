import React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Home from "./Home";

describe("NetGuard Run Demo Analysis", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    Element.prototype.scrollIntoView = vi.fn();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("starts, completes, and resets the shared analysis demo", async () => {
    render(<Home />);
    fireEvent.click(screen.getAllByRole("button", { name: "Run Demo Analysis" })[0]);
    expect(screen.getByText("Analysis in progress")).toBeTruthy();
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("0");

    for (let index = 0; index < 3; index += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(300);
      });
    }
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("27");
    expect(screen.getAllByText("Dispatching flows").length).toBeGreaterThan(0);

    for (let index = 0; index < 12; index += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(300);
      });
    }
    expect(screen.getByText("Analysis complete")).toBeTruthy();
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("100");
    fireEvent.click(screen.getByRole("button", { name: "Run Again" }));
    expect(screen.getByText("Analysis in progress")).toBeTruthy();
    expect(screen.getByRole("progressbar").getAttribute("aria-valuenow")).toBe("0");
  });
});
