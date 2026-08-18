import { describe, expect, it } from "vitest";
import {
  demoAlerts,
  demoRunReducer,
  demoSummary,
  getDemoRunState,
  hasConsistentPacketAccounting,
  initialDemoRun,
  reportObject,
} from "./netguardDemo";

describe("NetGuard demo data", () => {
  it("keeps packet accounting internally consistent", () => {
    expect(hasConsistentPacketAccounting()).toBe(true);
    expect(reportObject.summary.input_packets).toBe(
      reportObject.summary.forwarded_packets + reportObject.summary.dropped_packets,
    );
  });

  it("contains the exact threat-detector slugs used in the alert feed", () => {
    expect(demoAlerts.map((alert) => alert.detector)).toEqual([
      "port_scan",
      "dns_tunneling",
      "data_exfiltration",
    ]);
    expect(reportObject.summary.alerts).toBe(demoSummary.alerts);
  });

  it("models a resettable staged analysis lifecycle", () => {
    expect(getDemoRunState(0)).toMatchObject({ progress: 0, phaseIndex: 0, isComplete: false });
    expect(getDemoRunState(42)).toMatchObject({ progress: 42, phaseIndex: 1, isComplete: false });
    expect(getDemoRunState(72)).toMatchObject({ progress: 72, phaseIndex: 2, isComplete: false });
    expect(getDemoRunState(100)).toMatchObject({ progress: 100, phaseIndex: 3, isComplete: true });
    expect(getDemoRunState(-5)).toMatchObject({ progress: 0, phaseIndex: 0, isComplete: false });
  });

  it("transitions from start through completion and supports a rerun reset", () => {
    const started = demoRunReducer(initialDemoRun, { type: "start" });
    const complete = demoRunReducer(started, { type: "advance", amount: 100 });
    const restarted = demoRunReducer(complete, { type: "start" });
    expect(started).toEqual({ progress: 0, status: "running" });
    expect(complete).toEqual({ progress: 100, status: "complete" });
    expect(restarted).toEqual({ progress: 0, status: "running" });
  });
});
