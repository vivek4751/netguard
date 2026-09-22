import { describe, expect, it } from "vitest";
import { execute, validatePcap } from "./runner";
import { optionsSchema } from "../../shared/netguard";

describe("NetGuard runner boundaries", () => {
  it("rejects empty, PCAPNG and invalid capture headers", () => {
    expect(() => validatePcap(Buffer.alloc(0))).toThrow();
    const b = Buffer.alloc(24); b.writeUInt32LE(0x0a0d0d0a);
    expect(() => validatePcap(b)).toThrow(/classic PCAP/);
  });
  it("accepts bounded Ethernet classic PCAP header", () => {
    const b = Buffer.alloc(24); b.writeUInt32LE(0xa1b2c3d4); b.writeUInt16LE(2, 4); b.writeUInt16LE(4, 6); b.writeUInt32LE(65535, 16); b.writeUInt32LE(1, 20);
    expect(() => validatePcap(b)).not.toThrow();
  });
  it("rejects command-like values and unknown options", () => {
    expect(optionsSchema.safeParse({deny_ips: ["127.0.0.1;id"]}).success).toBe(false);
    expect(optionsSchema.safeParse({binary: "/bin/sh"}).success).toBe(false);
    expect(optionsSchema.safeParse({deny_domains: ["not..valid"]}).success).toBe(false);
  });
  it("reports nonzero exit and missing executable", async () => {
    await expect(execute(process.execPath, ["-e", "process.exit(2)"], {timeoutMs: 2000})).rejects.toThrow(/rejected/);
    await expect(execute("/netguard-does-not-exist", [], {timeoutMs: 2000})).rejects.toThrow(/unavailable/);
  });
  it("kills a hung process on timeout", async () => {
    await expect(execute(process.execPath, ["-e", "setInterval(()=>{},1000)"], {timeoutMs: 80})).rejects.toThrow(/timed out/);
  });
  it("cancels on AbortSignal", async () => {
    const controller = new AbortController(); controller.abort();
    await expect(execute(process.execPath, [], {timeoutMs: 2000, signal: controller.signal})).rejects.toThrow(/cancelled/);
  });
});
