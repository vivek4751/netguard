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

  it("expands a concise overview card to reveal its focused workspace link", () => {
    render(<Home />);
    const overview = document.querySelector("details.overview-item") as HTMLDetailsElement;
    expect(overview.open).toBe(false);
    fireEvent.click(screen.getByText("Findings & flows"));
    expect(overview.open).toBe(true);
    expect(screen.getByText("3 detector findings")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open Findings & flows" }).getAttribute("href")).toBe("/analysis");
  });
});
