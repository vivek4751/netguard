import express from "express";
import type { Server } from "node:http";
import { once } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAnalysisRouter } from "./routes";
import { AnalysisError } from "./runner";
let server: Server | undefined;
let closeRouter: (() => Promise<void>) | undefined;
afterEach(async () => { if (server) { const s = server; server = undefined; s.closeAllConnections(); await new Promise<void>((resolve, reject) => s.close(e => e ? reject(e) : resolve())); } await closeRouter?.(); });
async function setup(auth: () => Promise<string> = async () => "user", run = vi.fn(async () => { throw new AnalysisError("test engine failure", 422); })) {
  const app = express(); const api = createAnalysisRouter({authenticate: auth, run}); closeRouter = api.close; app.use("/api", api.router);
  server = app.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); if (!address || typeof address === "string") throw Error("No port");
  return {url: `http://127.0.0.1:${address.port}/api`, run};
}
function pcap() { const b = Buffer.alloc(24); b.writeUInt32LE(0xa1b2c3d4); b.writeUInt16LE(2,4); b.writeUInt16LE(4,6); b.writeUInt32LE(65535,16); b.writeUInt32LE(1,20); return b; }
describe("analysis route", () => {
  it("rejects unauthenticated upload before engine execution", async () => {const {url,run} = await setup(async () => {throw Error("unauthorized");}); const r = await fetch(`${url}/analyze`, {method:"POST",body:pcap(),headers:{"Content-Type":"application/octet-stream"}});expect(r.status).toBe(401);expect(run).not.toHaveBeenCalled();});
  it("rejects unsupported media and malformed capture", async () => {const {url,run} = await setup();expect((await fetch(`${url}/analyze`,{method:"POST",body:"bad",headers:{"Content-Type":"text/plain"}})).status).toBe(415);expect((await fetch(`${url}/analyze`,{method:"POST",body:"bad",headers:{"Content-Type":"application/octet-stream"}})).status).toBe(400);expect(run).not.toHaveBeenCalled();});
  it("rejects unexpected origins", async () => {const {url,run} = await setup();const r=await fetch(`${url}/analyze`,{method:"POST",body:pcap(),headers:{"Content-Type":"application/octet-stream",Origin:"https://evil.invalid"}});expect(r.status).toBe(403);expect(run).not.toHaveBeenCalled();});
  it("passes validated input to runner and returns engine failure", async () => {const {url,run} = await setup();const r=await fetch(`${url}/analyze`,{method:"POST",body:pcap(),headers:{"Content-Type":"application/octet-stream"}});expect(r.status).toBe(422);expect(run).toHaveBeenCalledOnce();});
  it("does not expose unknown or unauthorized artifacts", async () => {const {url}=await setup();expect((await fetch(`${url}/analysis/00000000-0000-4000-8000-000000000000/filtered.pcap`)).status).toBe(404);});
});
