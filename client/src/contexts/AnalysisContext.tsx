import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import { COOKIE_NAME } from "@shared/const";
import { analysisResponseSchema, MAX_PCAP_BYTES, optionsSchema, type AnalysisOptions, type AnalysisResponse } from "@shared/netguard";
type State = {
  mode: "demo" | "live"; status: "idle" | "running" | "complete" | "error"; error: string;
  result: AnalysisResponse | null; filename: string; token: string;
  setToken: (token: string) => void; setMode: (mode: "demo" | "live") => void;
  analyze: (file: File, options: AnalysisOptions) => Promise<void>; cancel: () => void;
  download: (artifact: "filtered.pcap" | "findings.json") => Promise<void>;
};
const fallback: State = {mode:"demo",status:"idle",error:"",result:null,filename:"",token:"",setToken:()=>{},setMode:()=>{},analyze:async()=>{},cancel:()=>{},download:async()=>{}};
const Context = createContext<State>(fallback);
export const useAnalysis = () => useContext(Context);
const apiBase = (import.meta.env.VITE_NETGUARD_API_URL ?? "").replace(/\/$/, "");
function authHeaders(token: string): Record<string,string> {
  if (token) return {Authorization: `Bearer ${token}`};
  // Never forward a session token to a different origin. Split deployments use an explicit operator token.
  if (apiBase && new URL(apiBase, window.location.origin).origin !== window.location.origin) return {};
  try {
    const pair = sessionStorage.getItem("manus-cookie")?.split(";").find(s => s.trim().startsWith(`${COOKIE_NAME}=`));
    const value = pair?.trim().slice(COOKIE_NAME.length + 1);
    return value ? {Authorization: `Bearer ${value}`} : {};
  } catch { return {}; }
}
export function AnalysisProvider({children}: {children: React.ReactNode}) {
  const [mode,setMode] = useState<State["mode"]>("demo");
  const [status,setStatus] = useState<State["status"]>("idle");
  const [error,setError] = useState("");
  const [result,setResult] = useState<AnalysisResponse|null>(null);
  const [filename,setFilename] = useState("");
  const [token,saveToken] = useState("");
  const current = useRef<AbortController|null>(null);
  useEffect(() => () => current.current?.abort(), []);
  const setToken = (value: string) => {current.current?.abort();setResult(null);setStatus("idle");setError("");saveToken(value);};
  const analyze = async (file: File, options: AnalysisOptions) => {
    if (current.current) return;
    setMode("live");setResult(null);setError("");setFilename(file.name);
    if (!file.name.toLowerCase().endsWith(".pcap") || file.size < 24 || file.size > MAX_PCAP_BYTES) {setStatus("error");setError("Choose a classic .pcap file between 24 bytes and 32 MiB.");return;}
    const valid = optionsSchema.safeParse(options);
    if (!valid.success) {setStatus("error");setError("Invalid detection thresholds or policy rules.");return;}
    const controller = new AbortController();current.current=controller;setStatus("running");
    const timeout = window.setTimeout(() => controller.abort(), 60000);
    try {
      const response = await fetch(`${apiBase}/api/analyze`, {method:"POST",credentials:"include",signal:controller.signal,
        headers:{"Content-Type":"application/octet-stream","X-NetGuard-Options":JSON.stringify(valid.data),...authHeaders(token)},body:file});
      const contentType = response.headers.get("content-type") ?? "";
      if (!contentType.includes("application/json")) throw Error("Analysis API unavailable. Deploy the backend and configure its URL.");
      const data: unknown = await response.json();
      if (!response.ok) throw Error(typeof data === "object" && data && "error" in data ? String(data.error) : `Analysis failed (${response.status}).`);
      setResult(analysisResponseSchema.parse(data));setStatus("complete");
    } catch (cause) {setStatus("error");setError(controller.signal.aborted ? "Analysis cancelled or timed out." : cause instanceof Error ? cause.message : "Analysis failed.");}
    finally {window.clearTimeout(timeout);current.current=null;}
  };
  const download = async (artifact: "filtered.pcap" | "findings.json") => {
    if (!result) return;
    try {
      if (Date.now() >= result.expiresAt) throw Error("Download expired. Run the analysis again.");
      const response = await fetch(`${apiBase}/api/analysis/${result.id}/${artifact}`, {credentials:"include",headers:authHeaders(token)});
      if (!response.ok) throw Error("Download unavailable, unauthorized, or expired.");
      const url=URL.createObjectURL(await response.blob());const a=document.createElement("a");a.href=url;a.download=artifact;a.click();window.setTimeout(()=>URL.revokeObjectURL(url),1000);
    } catch (cause) {setError(cause instanceof Error ? cause.message : "Download failed.");}
  };
  return <Context.Provider value={{mode,status,error,result,filename,token,setToken,setMode,analyze,cancel:()=>current.current?.abort(),download}}>{children}</Context.Provider>;
}
