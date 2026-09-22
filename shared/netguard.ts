import { z } from "zod";
export const MAX_PCAP_BYTES = 32 * 1024 * 1024;
const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const ipv4 = z.string().regex(/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/).refine(s => s.split(".").every(p => Number(p) <= 255), "Invalid IPv4 address");
const domain = z.string().max(253).regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/);
export const optionsSchema = z.object({
  workers: z.number().int().min(1).max(8).default(4),
  scan_ports: z.number().int().min(2).max(65535).default(20),
  scan_hosts: z.number().int().min(2).max(100000).default(30),
  dns_queries: z.number().int().min(2).max(100000).default(8),
  window_seconds: z.number().min(1).max(3600).default(60),
  dns_entropy: z.number().min(0).max(6).default(3.5),
  exfil_bytes: z.number().int().min(1).max(MAX_PCAP_BYTES).default(1048576),
  deny_ips: z.array(ipv4).max(100).default([]),
  deny_domains: z.array(domain).max(100).default([]),
}).strict();
export type AnalysisOptions = z.infer<typeof optionsSchema>;
const alert = z.object({
  id: count, detector: z.enum(["port_scan", "host_scan", "dns_tunneling", "data_exfiltration"]),
  severity: z.enum(["high", "medium", "low"]), score: z.number().min(0).max(100),
  source_ip: ipv4, destination_ip: ipv4, destination_port: z.number().int().min(0).max(65535),
  domain: z.string().max(253), explanation: z.string().max(2000),
  evidence: z.record(z.string(), z.union([z.string(), z.number().finite(), z.boolean()])),
});
export const reportSchema = z.object({
  schema_version: z.literal(1),
  summary: z.object({input_packets: count, parsed_packets: count, unsupported_packets: count, malformed_dns_packets: count,
    forwarded_packets: count, dropped_packets: count, total_bytes: count, active_flows: count, alerts: count,
    elapsed_seconds: z.number().positive(), packets_per_second: z.number().nonnegative(), megabytes_per_second: z.number().nonnegative()}),
  alerts: z.array(alert).max(100000),
  flows: z.array(z.object({source: z.string(), destination: z.string(), protocol: z.enum(["TCP", "UDP"]), packets: count, bytes: count,
    bytes_first_direction: count, bytes_reverse_direction: count, domain: z.string(), app: z.string(), state: z.enum(["Allowed", "Blocked", "Flagged"]),
    dropped_packets: count, first_seen: z.number().nonnegative(), last_seen: z.number().nonnegative()})).max(100000),
  policies: z.array(z.object({type: z.enum(["IP deny", "Domain deny"]), rule: z.string(), dropped: count, description: z.string()})).max(200),
  configuration: optionsSchema.omit({deny_ips: true, deny_domains: true}),
  limitations: z.array(z.string()),
}).superRefine((r, ctx) => {
  const s = r.summary;
  if (s.input_packets !== s.parsed_packets + s.unsupported_packets || s.input_packets !== s.forwarded_packets + s.dropped_packets || s.alerts !== r.alerts.length || s.active_flows !== r.flows.length || r.policies.reduce((n, p) => n + p.dropped, 0) !== s.dropped_packets)
    ctx.addIssue({code: "custom", message: "Engine report accounting mismatch"});
});
export type AnalysisReport = z.infer<typeof reportSchema>;
export const analysisResponseSchema = z.object({id: z.string().uuid(), report: reportSchema, expiresAt: z.number().int().positive()});
export type AnalysisResponse = z.infer<typeof analysisResponseSchema>;
