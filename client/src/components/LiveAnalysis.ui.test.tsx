import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AnalysisProvider } from "../contexts/AnalysisContext";
import LiveAnalysis from "./LiveAnalysis";
afterEach(() => {cleanup();vi.unstubAllGlobals();});
describe("Live PCAP upload", () => {
  it("validates file selection without making a request", () => {
    const fetch = vi.fn();vi.stubGlobal("fetch",fetch);
    render(<AnalysisProvider><LiveAnalysis /></AnalysisProvider>);
    expect((screen.getByRole("button",{name:"Analyze PCAP"}) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("PCAP file"),{target:{files:[new File(["bad"],"bad.pcap")]}});
    fireEvent.click(screen.getByRole("button",{name:"Analyze PCAP"}));
    expect(screen.getByRole("alert").textContent).toMatch(/24 bytes/);expect(fetch).not.toHaveBeenCalled();
  });
  it("shows backend errors without substituting demo results", async () => {
    vi.stubGlobal("fetch",vi.fn().mockResolvedValue({ok:false,status:401,headers:new Headers({"content-type":"application/json"}),json:async()=>({error:"Sign in required"})}));
    render(<AnalysisProvider><LiveAnalysis /></AnalysisProvider>);
    fireEvent.change(screen.getByLabelText("PCAP file"),{target:{files:[new File([new Uint8Array(24)],"test.pcap")]}});
    fireEvent.click(screen.getByRole("button",{name:"Analyze PCAP"}));
    await waitFor(()=>expect(screen.getByRole("alert").textContent).toContain("Sign in required"));
    expect(screen.queryByText("Real analysis complete")).toBeNull();
  });
});
