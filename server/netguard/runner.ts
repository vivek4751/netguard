import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { MAX_PCAP_BYTES, optionsSchema, reportSchema, type AnalysisOptions, type AnalysisReport } from "../../shared/netguard";

export class AnalysisError extends Error {
  constructor(message: string, public status = 500) { super(message); }
}
export function validatePcap(b: Buffer) {
  if (b.length < 24 || b.length > MAX_PCAP_BYTES) throw new AnalysisError("Capture must be between 24 bytes and 32 MiB.", 400);
  const magic = b.readUInt32LE(0);
  const little = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d;
  if (!little && magic !== 0xd4c3b2a1 && magic !== 0x4d3cb2a1) throw new AnalysisError("Only classic PCAP is supported; convert PCAPNG first.", 400);
  const u16 = (p: number) => little ? b.readUInt16LE(p) : b.readUInt16BE(p);
  const u32 = (p: number) => little ? b.readUInt32LE(p) : b.readUInt32BE(p);
  if (u16(4) !== 2 || u16(6) !== 4 || u32(20) !== 1 || !u32(16) || u32(16) > 262144) throw new AnalysisError("Expected PCAP 2.4 with Ethernet link type and bounded snaplen.", 400);
}
export function execute(binary: string, args: string[], options: {timeoutMs: number; signal?: AbortSignal; cwd?: string}): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    if (options.signal?.aborted) { reject(new AnalysisError("Analysis cancelled.", 499)); return; }
    const child = spawn(binary, args, {shell: false, cwd: options.cwd, windowsHide: true,
      env: {PATH: "/usr/bin:/bin", LANG: "C", HOME: options.cwd ?? tmpdir()}, stdio: ["ignore", "ignore", "pipe"]});
    let failure: AnalysisError | undefined;
    let stderrBytes = 0;
    const kill = (error: AnalysisError) => { failure ??= error; child.kill("SIGKILL"); };
    const timer = setTimeout(() => kill(new AnalysisError("Analysis timed out.", 504)), options.timeoutMs);
    const abort = () => kill(new AnalysisError("Analysis cancelled.", 499));
    options.signal?.addEventListener("abort", abort, {once: true});
    if (options.signal?.aborted) abort();
    const cleanup = () => { clearTimeout(timer); options.signal?.removeEventListener("abort", abort); };
    child.stderr.on("data", (chunk: Buffer) => { stderrBytes += chunk.length; if (stderrBytes > 65536) kill(new AnalysisError("Engine diagnostic output exceeded limit.", 502)); });
    child.once("error", () => { cleanup(); reject(new AnalysisError("NetGuard executable unavailable. Check backend deployment.", 503)); });
    child.once("close", code => { cleanup(); if (failure) reject(failure); else if (code !== 0) reject(new AnalysisError("Engine rejected capture or options. Check format, timestamps and packet limits.", 422)); else resolvePromise(); });
  });
}
export type RunResult = {report: AnalysisReport; directory: string; reportPath: string; filteredPath: string; dispose: () => Promise<void>};
export async function runAnalysis(capture: Buffer, options: AnalysisOptions, signal?: AbortSignal): Promise<RunResult> {
  validatePcap(capture);
  const config = optionsSchema.parse(options);
  const directory = await mkdtemp(join(tmpdir(), "netguard-"));
  const dispose = () => rm(directory, {recursive: true, force: true});
  try {
    const input = join(directory, "input.pcap"), reportPath = join(directory, "findings.json"), filteredPath = join(directory, "filtered.pcap");
    const configPath = join(directory, "options.json");
    await writeFile(input, capture, {mode: 0o600});
    await writeFile(configPath, JSON.stringify(config), {mode: 0o600});
    const binary = process.env.NETGUARD_BINARY || resolve("engine/build/netguard");
    if (!isAbsolute(binary)) throw new AnalysisError("NETGUARD_BINARY must be an absolute path.", 503);
    await execute(binary, ["analyze", input, "--report", reportPath, "--filtered", filteredPath, "--config", configPath], {timeoutMs: 30000, signal, cwd: directory});
    if ((await stat(reportPath)).size > 64 * 1024 * 1024 || (await stat(filteredPath)).size > MAX_PCAP_BYTES) throw new AnalysisError("Engine output exceeds limit.", 502);
    const parsed = reportSchema.safeParse(JSON.parse(await readFile(reportPath, "utf8")));
    if (!parsed.success) throw new AnalysisError("Invalid engine report contract.", 502);
    await rm(input); await rm(configPath);
    return {report: parsed.data, directory, reportPath, filteredPath, dispose};
  } catch (error) { await dispose(); if (error instanceof AnalysisError) throw error; throw new AnalysisError("Engine output could not be validated.", 502); }
}
