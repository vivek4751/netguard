export type Severity = "high" | "medium";

export type NetGuardAlert = {
  detector: "port_scan" | "dns_tunneling" | "data_exfiltration";
  severity: Severity;
  score: number;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  domain: string;
  explanation: string;
  evidence: Array<[string, string]>;
};

export const demoSummary = {
  inputPackets: 77,
  parsedPackets: 77,
  forwardedPackets: 70,
  droppedPackets: 7,
  activeFlows: 27,
  throughput: 9.13,
  alerts: 3,
};

export const analysisPhases = [
  { label: "Reading capture", detail: "campus_edge_sample.pcap · 6.3 KB", checkpoint: 18 },
  { label: "Dispatching flows", detail: "Hashing 5-tuples across 4 workers", checkpoint: 42 },
  { label: "Inspecting payloads", detail: "TLS SNI · DNS queries · policy rules", checkpoint: 72 },
  { label: "Writing evidence", detail: "Filtered PCAP + explainable JSON report", checkpoint: 100 },
] as const;

export function getDemoRunState(progress: number) {
  const normalizedProgress = Math.max(0, Math.min(100, progress));
  const phaseIndex = normalizedProgress < 25 ? 0 : normalizedProgress < 48 ? 1 : normalizedProgress < 78 ? 2 : 3;
  return {
    progress: normalizedProgress,
    phaseIndex,
    isComplete: normalizedProgress === 100,
  };
}

export type DemoRun = {
  progress: number;
  status: "idle" | "running" | "complete";
};

export type DemoRunAction =
  | { type: "start" }
  | { type: "advance"; amount: number };

export const initialDemoRun: DemoRun = { progress: 0, status: "idle" };

export function demoRunReducer(state: DemoRun, action: DemoRunAction): DemoRun {
  if (action.type === "start") return initialDemoRun.progress === state.progress && state.status === "running" ? state : { progress: 0, status: "running" };
  if (state.status !== "running") return state;
  const progress = Math.max(0, Math.min(100, state.progress + action.amount));
  return { progress, status: progress === 100 ? "complete" : "running" };
}

export const demoAlerts: NetGuardAlert[] = [
  {
    detector: "port_scan",
    severity: "high",
    score: 35,
    sourceIp: "10.0.0.10",
    destinationIp: "10.0.0.20",
    destinationPort: 0,
    domain: "",
    explanation: "One source contacted many destination ports within a short time window.",
    evidence: [
      ["unique_ports", "10"],
      ["window_seconds", "60"],
      ["tcp_syn_packets", "12"],
    ],
  },
  {
    detector: "dns_tunneling",
    severity: "high",
    score: 40,
    sourceIp: "10.0.0.10",
    destinationIp: "8.8.8.8",
    destinationPort: 53,
    domain: "1612dd272d1371c17149d439536b.tunnel.example",
    explanation: "High-entropy DNS labels were queried repeatedly in a short time window.",
    evidence: [
      ["queries", "8"],
      ["average_label_entropy", "3.24"],
      ["average_label_length", "28"],
    ],
  },
  {
    detector: "data_exfiltration",
    severity: "high",
    score: 45,
    sourceIp: "10.0.0.10",
    destinationIp: "10.0.0.30",
    destinationPort: 443,
    domain: "",
    explanation: "A flow exceeded the configured outbound byte threshold.",
    evidence: [
      ["bytes_first_direction", "1,062"],
      ["threshold_bytes", "1,000"],
      ["flow_packets", "3"],
    ],
  },
];

export const demoFlows = [
  { source: "10.0.0.10:45000", destination: "10.0.0.20:3011", protocol: "TCP", packets: 1, bytes: "54 B", domain: "—", app: "Unknown", state: "Flagged" },
  { source: "10.0.0.10:50008", destination: "8.8.8.8:53", protocol: "UDP", packets: 1, bytes: "90 B", domain: "…tunnel.example", app: "DNS", state: "Flagged" },
  { source: "10.0.0.10:46000", destination: "10.0.0.30:443", protocol: "TCP", packets: 5, bytes: "1.6 KB", domain: "—", app: "TLS", state: "Flagged" },
  { source: "192.168.1.50:51422", destination: "142.250.193.14:443", protocol: "TCP", packets: 4, bytes: "488 B", domain: "www.youtube.com", app: "YouTube", state: "Blocked" },
  { source: "192.168.1.24:51909", destination: "13.107.246.45:443", protocol: "TCP", packets: 9, bytes: "1.2 KB", domain: "login.microsoft.com", app: "Microsoft", state: "Allowed" },
  { source: "192.168.1.17:53644", destination: "140.82.112.4:443", protocol: "TCP", packets: 7, bytes: "908 B", domain: "api.github.com", app: "GitHub", state: "Allowed" },
] as const;

export const policies = [
  { type: "IP deny", rule: "192.168.1.50", dropped: 4, description: "Matched source or destination IP rule" },
  { type: "Domain deny", rule: "youtube.com", dropped: 3, description: "Matched normalized SNI domain suffix" },
] as const;

export const detectorExplainers = [
  {
    key: "01",
    name: "Port scan",
    slug: "port_scan",
    description: "Counts distinct destination ports for TCP SYN traffic from one source during a bounded observation window.",
    example: "--scan-ports 20 --scan-window 60",
    metric: "Distinct ports / source",
  },
  {
    key: "02",
    name: "Host scan",
    slug: "host_scan",
    description: "Identifies a source that probes many destination hosts on the same service or across a short time interval.",
    example: "--scan-hosts 30 --scan-window 60",
    metric: "Distinct hosts / source",
  },
  {
    key: "03",
    name: "DNS tunneling",
    slug: "dns_tunneling",
    description: "Flags repeated queries with unusually high-entropy first labels, a signal that DNS may carry encoded data.",
    example: "--dns-queries 8 --dns-entropy 3.0",
    metric: "Entropy + query rate",
  },
  {
    key: "04",
    name: "Data exfiltration",
    slug: "data_exfiltration",
    description: "Surfaces flows whose first direction exceeds a configured byte threshold and requires analyst review.",
    example: "--exfil-bytes 1048576",
    metric: "First-direction bytes",
  },
] as const;

export const reportObject = {
  summary: {
    input_packets: demoSummary.inputPackets,
    parsed_packets: demoSummary.parsedPackets,
    unsupported_packets: 0,
    forwarded_packets: demoSummary.forwardedPackets,
    dropped_packets: demoSummary.droppedPackets,
    total_bytes: 5738,
    active_flows: demoSummary.activeFlows,
    alerts: demoSummary.alerts,
    elapsed_seconds: 0.001,
    packets_per_second: 128471.654,
    megabytes_per_second: demoSummary.throughput,
  },
  alerts: demoAlerts.map((alert, index) => ({
    id: index + 1,
    detector: alert.detector,
    severity: alert.severity,
    score: alert.score,
    source_ip: alert.sourceIp,
    destination_ip: alert.destinationIp,
    destination_port: alert.destinationPort,
    domain: alert.domain,
    explanation: alert.explanation,
    evidence: Object.fromEntries(alert.evidence),
  })),
};

export const reportJson = JSON.stringify(reportObject, null, 2);

export function hasConsistentPacketAccounting() {
  return demoSummary.inputPackets === demoSummary.forwardedPackets + demoSummary.droppedPackets;
}
