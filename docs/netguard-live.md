# NetGuard: live PCAP engine and dashboard

## Status

Implementation candidate on `feature/netguard-live-engine`; main is unchanged. Compilation, tests, Docker build and browser acceptance checks have NOT been executed by the authoring environment. CI workflow creation through the connector failed. Do not treat this as a tested production release. Existing demo tests remain in place.

## Run locally with Docker

```bash
git clone --branch feature/netguard-live-engine https://github.com/vivek4751/netguard.git
cd netguard
docker build -t netguard:local .
export NETGUARD_API_TOKEN="$(openssl rand -hex 32)"
printf 'Local backend token: %s\n' "$NETGUARD_API_TOKEN"
docker run --rm --init --name netguard \
  -p 127.0.0.1:3000:3000 --memory=1536m --cpus=2 --pids-limit=128 \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=1g,mode=1777 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  -e NETGUARD_API_TOKEN \
  -e NETGUARD_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000 \
  netguard:local
```

Open `http://localhost:3000`. Enter the generated BACKEND token (not a GitHub token) in Live Engine, select an authorized `.pcap`, and click Analyze PCAP. Docker build runs CTest, TypeScript checks, Vitest and the production build; it fails if a gate fails. No passed result is claimed here.

Tokens and reports stay in browser memory, not localStorage. Reloading clears them. Operator-token holders share one identity; use existing OAuth for separate users. Existing OAuth requires the scaffold's database/OAuth environment configuration. An unconfigured OAuth service can log warnings even when using operator-token authentication.

## Native setup and required verification

Requires Linux, Node.js 22, pnpm 10.4.1, CMake, a C++17 compiler and nlohmann-json3-dev.

```bash
sudo apt-get update
sudo apt-get install -y cmake g++ nlohmann-json3-dev
corepack enable
corepack prepare pnpm@10.4.1 --activate
pnpm install --frozen-lockfile
cmake -S engine -B engine/build -DCMAKE_BUILD_TYPE=Debug
cmake --build engine/build -j2
ctest --test-dir engine/build --output-on-failure
pnpm check
pnpm test
NODE_ENV=production pnpm build
export NETGUARD_BINARY="$PWD/engine/build/netguard"
export NETGUARD_API_TOKEN="$(openssl rand -hex 32)"
pnpm dev
```

No lint script exists. Request a non-mutating formatting check with `pnpm exec prettier --check shared/netguard.ts server/netguard client/src/contexts/AnalysisContext.tsx client/src/components/LiveAnalysis.tsx`. Formatting has not been verified. Additional fuzzing, race detection and security review are recommended before public deployment.

## CLI

```bash
engine/build/netguard analyze input.pcap \
  --report findings.json --filtered filtered.pcap --config options.json
```

Config is optional. Input, report and filtered paths must differ. Nonzero exit means failure; CLI partial outputs may remain. The web wrapper removes its job directory on failure.

```json
{
  "workers": 4,
  "scan_ports": 20,
  "scan_hosts": 30,
  "dns_queries": 8,
  "window_seconds": 60,
  "dns_entropy": 3.5,
  "exfil_bytes": 1048576,
  "deny_ips": ["192.0.2.10"],
  "deny_domains": ["example.com"]
}
```

## API

| Route | Contract |
|---|---|
| POST /api/analyze | Authenticated raw PCAP body; application/octet-stream; optional JSON X-NetGuard-Options header. Returns id, expiresAt and report. Not multipart/form-data. |
| GET /api/analysis/:id/findings.json | Authenticated, owner-scoped report download. |
| GET /api/analysis/:id/filtered.pcap | Authenticated, owner-scoped filtered capture download. |

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $NETGUARD_API_TOKEN" \
  -H 'Content-Type: application/octet-stream' \
  -H 'X-NetGuard-Options: {"scan_ports":20}' \
  --data-binary @input.pcap http://localhost:3000/api/analyze
```

Use the returned ID in download routes and supply the same authorization. The version-1 report contains summary, alerts, flows, policies, configuration and limitations. Zod validates frontend/backend contracts and packet accounting. UI row previews cap at 200; downloads retain all rows.

## Architecture and scope

Reader validates capture records. Dispatcher assigns canonical bidirectional flow keys to workers. Each worker owns its flow map and evaluates policy rules. Ordered Output writes filtered packets and aggregates source-wide detector windows across workers. Bounded queues apply backpressure; capture limits bound flow/window accumulation. Scan/DNS aggregation is single-threaded for correctness; no throughput benchmark is claimed.

| Detector | Implemented heuristic |
|---|---|
| Port scan | Distinct TCP SYN ports per source/destination pair within the capture-time window. |
| Host scan | Distinct TCP SYN destination hosts per source within the window. |
| DNS tunneling | Repeated UDP DNS query first labels of at least 16 characters exceeding the entropy threshold. |
| Unusual transfer | First-observed-direction captured frame bytes reach the threshold; not proof of outbound exfiltration. |

Classic Ethernet PCAP 2.4 only; IPv4 TCP/UDP, up to two VLAN tags. PCAPNG, IPv6, fragments and TCP stream reassembly are unsupported. No checksum validation, TLS SNI parsing or encrypted DNS inspection. Capture timestamps must be nondecreasing. Limits: 32 MiB, 100000 packets, 1-8 workers. Unsupported protocol packets are counted and forwarded without full inspection. Malformed DNS is counted separately.

IP rules match exact parsed source/destination IPv4 addresses, not CIDRs. Domain rules match lowercase DNS suffixes with dot boundaries, only for observed unencrypted UDP DNS queries. They do not block subsequent connections or change a firewall. First matching IP rule wins, then first matching domain rule; each dropped packet is attributed once. Filtered PCAP preserves original order.

Alerts are heuristic, not proof. One alert per detector/group per run; scores are not probabilities. Flow state reflects policy drops or transfer thresholds; source-wide scan/DNS findings stay in the alert feed. Allowed does not mean safe.

## Security, retention and deployment

Uploads require existing OAuth authentication or a configured NETGUARD_API_TOKEN of at least 32 characters. Personal operator-token mode is not multi-tenant isolation. All holders share artifact ownership. Supply secrets at runtime, never as VITE variables or build arguments.

The API uses raw bounded uploads, isolated temporary directories, fixed executable arguments with shell disabled, a minimal child environment, 30-second engine timeout, 20-second upload timeout, two simultaneous jobs globally and one per identity. A 30-second cooldown follows accepted capture validation. Up to ten retained/in-flight jobs; artifacts expire after ten minutes and cleanup runs every 30 seconds. Input is deleted after processing. A crash can leave temporary directories: use ephemeral container tmpfs as shown. Expiry may race a download, requiring a rerun.

The engine child shares the container security boundary; it is not a per-job hardened sandbox. Use the container resource restrictions and a trusted reverse proxy with authentication/rate limits/TLS. Public deployment requires further review. Raw packet captures can contain private data.

Recommended hosting: the complete Express + C++ Docker container. Existing Vercel configuration serves frontend assets only and does not deploy the native analysis backend. For split hosting, build with VITE_NETGUARD_API_URL set to the HTTPS backend origin and set NETGUARD_ALLOWED_ORIGINS on the backend to the exact frontend origin. Never forward existing session tokens to a different origin; the client uses an explicit operator token for that case. No deployment was performed.

## Acceptance checks before merge

Run all build/test commands above. Then upload an authorized capture in the browser, inspect actual counters and all four detector cases, download both artifacts, reopen filtered PCAP in Wireshark, test cancellation, malformed input, expiry, same-user access and different-user denial. Existing tests cover selected engine, process, API and UI boundaries, not full acceptance/security coverage. Request fixes if any gate fails; do not merge solely because code exists.
