/**
 * ScanWeasel v1 scanner — TypeScript reimplementation of a bounded
 * harness-style passive + limited path check set.
 *
 * Designed to finish inside typical Vercel serverless time limits.
 * Not a full port of harness_v3 (no long stealth delays, no 70+ paths).
 */

import type {
  ScanResult,
  HeaderCheck,
  CspCheck,
  CookieFinding,
  PathResult,
  Severity,
} from "./types";
import { assertSafeScanTarget, assertSafeFetchUrl } from "./url-safety";

const FETCH_TIMEOUT_MS = 8_000;
const MAX_BODY_BYTES = 800_000;

const EXPECTED_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
] as const;

/** Small, high-signal path list for v1 */
const PATHS = [
  "robots.txt",
  "sitemap.xml",
  ".well-known/security.txt",
  "security.txt",
  ".env",
  ".git/HEAD",
  "package.json",
  "wp-login.php",
  "admin/",
];

const SENSITIVE_PATHS = new Set([
  ".env",
  ".git/HEAD",
  "package.json",
]);

const SCANNER_UA =
  "ScanWeasel/1.0 (+https://scanweasel.example; passive site check; self-owned sites only)";

async function normalizeTarget(input: string): Promise<string> {
  // DNS + public-IP checks live in assertSafeScanTarget
  return assertSafeScanTarget(input);
}

async function fetchLimited(
  url: string,
  init: RequestInit = {}
): Promise<{ response: Response; body: ArrayBuffer }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": SCANNER_UA,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        ...(init.headers || {}),
      },
    });

    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;

    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > MAX_BODY_BYTES) {
            reader.cancel().catch(() => {});
            break;
          }
          chunks.push(value);
        }
      }
    }

    const body = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      body.set(c, offset);
      offset += c.byteLength;
    }

    return { response, body: body.buffer };
  } finally {
    clearTimeout(timer);
  }
}

function headerMap(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

function detectChallenge(headers: Record<string, string>, bodyText: string): string[] {
  const notes: string[] = [];
  if (headers["cf-ray"] || headers["cf-mitigated"]) {
    notes.push("Cloudflare headers present");
  }
  const lower = bodyText.slice(0, 4000).toLowerCase();
  for (const sig of [
    "just a moment",
    "checking your browser",
    "cf-browser-verification",
    "attention required! | cloudflare",
    "enable javascript and cookies",
  ]) {
    if (lower.includes(sig)) notes.push(`Body matches challenge pattern: "${sig}"`);
  }
  return notes;
}

function parseCsp(raw: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of raw.split(";")) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length === 0 || !tokens[0]) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return directives;
}

function evaluateCsp(directives: Record<string, string[]>): CspCheck["findings"] {
  const findings: CspCheck["findings"] = [];
  const scriptSrc = directives["script-src"] || directives["default-src"];

  if (!scriptSrc) {
    findings.push({
      severity: "HIGH",
      issue: "No script-src or default-src — CSP provides little XSS protection.",
    });
  } else {
    const normalized = scriptSrc.map((s) => s.replace(/'/g, "").toLowerCase());
    if (normalized.includes("unsafe-inline")) {
      findings.push({
        severity: "HIGH",
        issue: "'unsafe-inline' allowed for scripts — weakens XSS protection.",
      });
    }
    if (normalized.includes("unsafe-eval")) {
      findings.push({
        severity: "HIGH",
        issue: "'unsafe-eval' present — eval()/Function still allowed.",
      });
    }
    if (scriptSrc.includes("*")) {
      findings.push({
        severity: "HIGH",
        issue: "Wildcard '*' allowed as a script source.",
      });
    }
  }

  const objectSrc = directives["object-src"] || directives["default-src"];
  if (!objectSrc || !objectSrc.some((s) => s.replace(/'/g, "").toLowerCase() === "none")) {
    findings.push({
      severity: "MEDIUM",
      issue: "object-src is not restricted to 'none'.",
    });
  }

  if (!directives["base-uri"]) {
    findings.push({
      severity: "MEDIUM",
      issue: "No base-uri directive — injected <base> tags could rewrite relative URLs.",
    });
  }

  if (!directives["frame-ancestors"]) {
    findings.push({
      severity: "LOW",
      issue: "No frame-ancestors — clickjacking relies solely on X-Frame-Options if present.",
    });
  }

  return findings;
}

function parseCookies(setCookieHeaders: string[]): CookieFinding[] {
  const findings: CookieFinding[] = [];

  for (const raw of setCookieHeaders) {
    const parts = raw.split(";").map((p) => p.trim());
    const name = parts[0]?.split("=")[0] || "(unknown)";
    const attrs: Record<string, string | true> = {};
    for (const p of parts.slice(1)) {
      const [k, v] = p.split("=");
      if (!k) continue;
      attrs[k.trim().toLowerCase()] = v !== undefined ? v.trim() : true;
    }

    const issues: string[] = [];
    if (!attrs["secure"]) issues.push("missing Secure");
    if (!attrs["httponly"]) issues.push("missing HttpOnly");
    const sameSite = typeof attrs["samesite"] === "string" ? attrs["samesite"] : null;
    if (!sameSite) issues.push("missing SameSite");
    else if (sameSite.toLowerCase() === "none" && !attrs["secure"]) {
      issues.push("SameSite=None without Secure");
    }

    findings.push({
      name,
      secure: Boolean(attrs["secure"]),
      httpOnly: Boolean(attrs["httponly"]),
      sameSite,
      issues,
    });
  }

  return findings;
}

/** Collect multiple Set-Cookie values (fetch may collapse them). */
function getSetCookies(res: Response): string[] {
  // undici/Next may expose getSetCookie when available
  const anyHeaders = res.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof anyHeaders.getSetCookie === "function") {
    return anyHeaders.getSetCookie();
  }
  const single = res.headers.get("set-cookie");
  return single ? [single] : [];
}

async function followHttpsHomepage(target: string): Promise<{
  response: Response;
  bodyText: string;
  finalUrl: string;
  hops: { url: string; status: number }[];
}> {
  let current = target;
  const hops: { url: string; status: number }[] = [];
  const originHost = new URL(target).hostname;

  for (let i = 0; i < 4; i++) {
    await assertSafeFetchUrl(current, originHost);
    const { response, body } = await fetchLimited(current);
    hops.push({ url: current, status: response.status });

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const loc = response.headers.get("location");
      if (!loc) break;
      const next = new URL(loc, current).toString();
      const nextHost = new URL(next).hostname;
      if (nextHost.toLowerCase() !== originHost.toLowerCase()) {
        // Do not follow off-domain redirects (SSRF / open-redirect abuse)
        hops.push({ url: next, status: -1 });
        const bodyText = new TextDecoder("utf-8", { fatal: false }).decode(body);
        return { response, bodyText, finalUrl: current, hops };
      }
      // Same host — still re-validate before the next hop
      await assertSafeFetchUrl(next, originHost);
      current = next;
      continue;
    }

    const bodyText = new TextDecoder("utf-8", { fatal: false }).decode(body);
    return { response, bodyText, finalUrl: current, hops };
  }

  await assertSafeFetchUrl(current, originHost);
  const { response, body } = await fetchLimited(current);
  const bodyText = new TextDecoder("utf-8", { fatal: false }).decode(body);
  return { response, bodyText, finalUrl: current, hops };
}

export async function runScan(rawUrl: string): Promise<ScanResult> {
  const target = await normalizeTarget(rawUrl);
  const scannedAt = new Date().toISOString();
  const issues: ScanResult["issues"] = [];
  const cleanAreas: string[] = [];

  // --- Homepage / headers ---
  let headersCheck: HeaderCheck = {
    present: {},
    missing: [...EXPECTED_HEADERS],
    statusCode: null,
    finalUrl: null,
    challengeSuspected: false,
    challengeNotes: [],
  };

  let bodyText = "";
  let homepageOk = false;

  try {
    const { response, bodyText: text, finalUrl } = await followHttpsHomepage(target);
    bodyText = text;
    homepageOk = response.status > 0;
    const h = headerMap(response);
    const present: Record<string, string> = {};
    const missing: string[] = [];

    for (const name of EXPECTED_HEADERS) {
      if (h[name]) present[name] = h[name];
      else missing.push(name);
    }

    const challengeNotes = detectChallenge(h, bodyText);
    headersCheck = {
      present,
      missing,
      statusCode: response.status,
      finalUrl,
      challengeSuspected: challengeNotes.length > 0,
      challengeNotes,
    };

    if (missing.length === 0) {
      cleanAreas.push("All checked security headers are present");
    } else {
      for (const m of missing) {
        const sev: Severity =
          m === "content-security-policy" ||
          m === "strict-transport-security" ||
          m === "x-content-type-options" ||
          m === "x-frame-options"
            ? "MEDIUM"
            : "LOW";
        issues.push({ severity: sev, title: `Missing security header: ${m}` });
      }
    }

    if (headersCheck.challengeSuspected) {
      issues.push({
        severity: "LOW",
        title:
          "Response may be a bot-challenge page — some results could reflect the challenge, not the app",
      });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return {
      target,
      scannedAt,
      headers: headersCheck,
      csp: { present: false, raw: null, findings: [] },
      cookies: [],
      httpDowngrade: {
        firstHopStatus: null,
        finalStatus: null,
        servedOverPlaintext: false,
      },
      cors: { acao: null, acac: null, finding: null },
      paths: [],
      cleanAreas: [],
      issues: [{ severity: "HIGH", title: `Could not fetch site: ${msg}` }],
      error: msg,
    };
  }

  // --- CSP ---
  let csp: CspCheck = { present: false, raw: null, findings: [] };
  const cspRaw = headersCheck.present["content-security-policy"] || null;
  if (cspRaw) {
    const directives = parseCsp(cspRaw);
    const findings = evaluateCsp(directives);
    csp = { present: true, raw: cspRaw, findings };
    if (findings.length === 0) {
      cleanAreas.push("Content-Security-Policy present with no obvious high-risk weaknesses in heuristic checks");
    } else {
      for (const f of findings) {
        issues.push({ severity: f.severity, title: f.issue });
      }
    }
  } else {
    // try meta (light)
    const metaMatch = bodyText.match(
      /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]+content=["']([^"']+)["']/i
    );
    if (metaMatch?.[1]) {
      const directives = parseCsp(metaMatch[1]);
      const findings = evaluateCsp(directives);
      csp = { present: true, raw: metaMatch[1], findings };
      for (const f of findings) {
        issues.push({ severity: f.severity, title: f.issue });
      }
    } else {
      csp = { present: false, raw: null, findings: [] };
      issues.push({
        severity: "HIGH",
        title: "No Content-Security-Policy found (header or meta)",
      });
    }
  }

  // --- Cookies (from a fresh homepage get so Set-Cookie is visible) ---
  let cookies: CookieFinding[] = [];
  try {
    const { response } = await fetchLimited(target);
    cookies = parseCookies(getSetCookies(response));
    if (cookies.length === 0) {
      cleanAreas.push("No cookies set on the homepage response");
    } else {
      let anyWeak = false;
      for (const c of cookies) {
        if (c.issues.length) {
          anyWeak = true;
          issues.push({
            severity: "MEDIUM",
            title: `Weak cookie flags on "${c.name}": ${c.issues.join(", ")}`,
          });
        }
      }
      if (!anyWeak) cleanAreas.push("Cookies present with Secure / HttpOnly / SameSite look set");
    }
  } catch {
    // non-fatal
  }

  // --- CORS ---
  let cors: ScanResult["cors"] = { acao: null, acac: null, finding: null };
  try {
    const { response } = await fetchLimited(target, {
      headers: { Origin: "https://evil-example-test.invalid" },
    });
    const acao = response.headers.get("access-control-allow-origin");
    const acac = response.headers.get("access-control-allow-credentials");
    let finding: string | null = null;
    if (acao === "*" && acac?.toLowerCase() === "true") {
      finding = "Wildcard ACAO combined with Allow-Credentials";
      issues.push({ severity: "HIGH", title: finding });
    } else if (acao === "https://evil-example-test.invalid") {
      finding = "Server reflects arbitrary Origin";
      issues.push({ severity: "MEDIUM", title: finding });
    } else {
      cleanAreas.push("CORS probe did not show an obvious misconfiguration on the homepage");
    }
    cors = { acao, acac, finding };
  } catch {
    // non-fatal
  }

  // --- HTTP downgrade ---
  let httpDowngrade: ScanResult["httpDowngrade"] = {
    firstHopStatus: null,
    finalStatus: null,
    servedOverPlaintext: false,
  };
  try {
    const httpUrl = target.replace(/^https:/, "http:");
    const originHost = new URL(target).hostname;
    await assertSafeFetchUrl(httpUrl, originHost);
    const { response } = await fetchLimited(httpUrl);
    const first = response.status;
    httpDowngrade = {
      firstHopStatus: first,
      finalStatus: first,
      servedOverPlaintext: first === 200,
    };
    if (first === 200) {
      issues.push({
        severity: "HIGH",
        title: "Plain HTTP returned 200 (content may be served unencrypted)",
      });
    } else if ([301, 302, 303, 307, 308].includes(first)) {
      cleanAreas.push("HTTP responds with a redirect (expected for HTTPS sites)");
    }
  } catch {
    cleanAreas.push("Plain HTTP check did not complete (often fine if HTTP is closed)");
  }

  // --- Paths ---
  const paths: PathResult[] = [];
  const originHost = new URL(target).hostname;
  for (const path of PATHS) {
    const url = new URL(path, target).toString();
    try {
      await assertSafeFetchUrl(url, originHost);
      const { response, body } = await fetchLimited(url);
      const size = body.byteLength;
      const entry: PathResult = {
        path,
        status: response.status,
        size,
      };

      if (response.status === 200 && size > 0 && SENSITIVE_PATHS.has(path)) {
        entry.severity = "HIGH";
        entry.note = "Sensitive path returned 200 with content";
        issues.push({
          severity: "HIGH",
          title: `Sensitive path publicly accessible: ${path}`,
        });
      }

      paths.push(entry);
    } catch (e) {
      paths.push({
        path,
        status: null,
        size: 0,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  const sensitiveExposed = paths.some((p) => p.severity === "HIGH");
  if (!sensitiveExposed) {
    cleanAreas.push(
      "Selected sensitive paths (.env, .git/HEAD, package.json) did not return public 200s"
    );
  }

  // Sort issues roughly by severity
  const order: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  issues.sort((a, b) => order[a.severity] - order[b.severity]);

  return {
    target,
    scannedAt,
    headers: headersCheck,
    csp,
    cookies,
    httpDowngrade,
    cors,
    paths,
    cleanAreas,
    issues,
  };
}
