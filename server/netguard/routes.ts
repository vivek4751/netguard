import { Router, type Express, type Request, type RequestHandler } from "express";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { MAX_PCAP_BYTES, optionsSchema } from "../../shared/netguard";
import { AnalysisError, runAnalysis, validatePcap, type RunResult } from "./runner";
import { sdk } from "../_core/sdk";

type Dependencies = {authenticate: (req: Request) => Promise<string>; run?: typeof runAnalysis};
type Artifact = RunResult & {owner: string; expiresAt: number};
export function createAnalysisRouter(deps: Dependencies) {
  const router = Router();
  const artifacts = new Map<string, Artifact>();
  const running = new Set<string>();
  const cooldown = new Map<string, number>();
  const controllers = new Set<AbortController>();
  let active = 0;
  const prune = async () => {
    const expired = [...artifacts].filter(([, a]) => a.expiresAt <= Date.now());
    for (const [id] of expired) artifacts.delete(id);
    for (const [owner, time] of cooldown) if (time <= Date.now()) cooldown.delete(owner);
    await Promise.all(expired.map(([, a]) => a.dispose().catch(() => undefined)));
  };
  const timer = setInterval(() => { void prune(); }, 30000); timer.unref();
  const originAllowed = (req: Request) => {
    const origin = req.get("origin");
    if (!origin) return req.get("sec-fetch-site") !== "cross-site";
    const configured = (process.env.NETGUARD_ALLOWED_ORIGINS ?? "").split(",").map(s => s.trim()).filter(Boolean);
    return configured.length ? configured.includes(origin) : origin === `${req.protocol}://${req.get("host")}`;
  };
  router.use((req, res, next) => {
    if (!req.path.startsWith("/analyze") && !req.path.startsWith("/analysis/")) { next(); return; }
    res.setHeader("Cache-Control", "no-store"); res.setHeader("X-Content-Type-Options", "nosniff");
    if (!originAllowed(req)) { res.status(403).json({error: "Origin not allowed."}); return; }
    if (req.get("origin")) { res.setHeader("Access-Control-Allow-Origin", req.get("origin")!); res.setHeader("Access-Control-Allow-Credentials", "true"); res.vary("Origin"); }
    if (req.method === "OPTIONS") { res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-NetGuard-Options"); res.sendStatus(204); return; }
    next();
  });
  const authenticate: RequestHandler = (req, res, next) => {
    void deps.authenticate(req).then(owner => { if (!owner) throw Error("No principal"); res.locals.netguardOwner = owner; next(); }).catch(() => res.status(401).json({error: "Sign in or supply a valid backend access token."}));
  };
  router.post("/analyze", authenticate, (req, res) => {
    void (async () => {
      const owner = String(res.locals.netguardOwner);
      if (active >= 2 || running.has(owner) || artifacts.size + active >= 10 || (cooldown.get(owner) ?? 0) > Date.now()) { res.setHeader("Retry-After", "30"); res.status(429).json({error: "Analysis capacity reached. Retry after 30 seconds; artifacts expire after 10 minutes."}); return; }
      const type = req.get("content-type")?.split(";")[0].trim();
      if (type !== "application/octet-stream" && type !== "application/vnd.tcpdump.pcap") { res.status(415).json({error: "Send the PCAP file as a raw binary body."}); return; }
      const length = req.get("content-length");
      if (length && (!/^\d+$/.test(length) || Number(length) > MAX_PCAP_BYTES)) { res.status(413).json({error: "PCAP upload exceeds 32 MiB."}); return; }
      let config;
      try { const raw = req.get("x-netguard-options") ?? "{}"; if (raw.length > 12000) throw Error("Options too large"); config = optionsSchema.parse(JSON.parse(raw)); }
      catch { res.status(400).json({error: "Invalid analysis options or policy rules."}); return; }
      active++; running.add(owner);
      const controller = new AbortController(); controllers.add(controller);
      const abort = () => controller.abort();
      req.once("aborted", abort); res.once("close", abort);
      const uploadTimer = setTimeout(() => { controller.abort(); req.destroy(); }, 20000);
      let result: RunResult | undefined;
      try {
        let size = 0; const chunks: Buffer[] = [];
        for await (const chunk of req) { const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += bytes.length; if (size > MAX_PCAP_BYTES) throw new AnalysisError("PCAP upload exceeds 32 MiB.", 413); chunks.push(bytes); }
        clearTimeout(uploadTimer);
        const capture = Buffer.concat(chunks, size); validatePcap(capture);
        if (controller.signal.aborted) throw new AnalysisError("Analysis cancelled.", 499);
        cooldown.set(owner, Date.now() + 30000);
        result = await (deps.run ?? runAnalysis)(capture, config, controller.signal);
        if (controller.signal.aborted) { await result.dispose(); result = undefined; return; }
        const id = randomUUID(), expiresAt = Date.now() + 10 * 60 * 1000;
        artifacts.set(id, {...result, owner, expiresAt});
        res.json({id, expiresAt, report: result.report});
      } catch (error) {
        if (result) await result.dispose().catch(() => undefined);
        if (!res.headersSent && !res.destroyed) res.status(error instanceof AnalysisError ? error.status : 500).json({error: error instanceof AnalysisError ? error.message : "Analysis failed."});
      } finally { clearTimeout(uploadTimer); req.off("aborted", abort); res.off("close", abort); controllers.delete(controller); running.delete(owner); active--; }
    })().catch(() => { if (!res.headersSent && !res.destroyed) res.status(500).json({error: "Analysis failed."}); });
  });
  router.get("/analysis/:id/:artifact", authenticate, (req, res) => {
    const artifact = artifacts.get(req.params.id);
    const name = req.params.artifact;
    if (!artifact || artifact.owner !== String(res.locals.netguardOwner) || artifact.expiresAt <= Date.now() || !["findings.json", "filtered.pcap"].includes(name)) { res.status(404).json({error: "Artifact not found or expired."}); return; }
    res.download(name === "findings.json" ? artifact.reportPath : artifact.filteredPath, name, error => { if (error && !res.headersSent) res.status(404).json({error: "Artifact unavailable."}); });
  });
  return {router, close: async () => {clearInterval(timer); for (const c of controllers) c.abort(); await Promise.all([...artifacts.values()].map(a => a.dispose().catch(() => undefined))); artifacts.clear();}};
}
export function registerAnalysisRoutes(app: Express) {
  const api = createAnalysisRouter({authenticate: async req => {
    const configured = process.env.NETGUARD_API_TOKEN;
    const supplied = req.get("authorization")?.replace(/^Bearer /, "");
    if (configured && configured.length >= 32 && supplied) {
      const hash = (s: string) => createHash("sha256").update(s).digest();
      if (timingSafeEqual(hash(configured), hash(supplied))) return "operator";
    }
    const user = await sdk.authenticateRequest(req);
    if (user.isCron) throw Error("Interactive authentication required");
    return user.openId;
  }});
  app.use("/api", api.router);
  return api;
}
