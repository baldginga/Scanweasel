/**
 * Rate limiter for ScanWeasel.
 *
 * IP extraction prefers platform-provided headers and ignores client-supplied
 * X-Forwarded-For spoofing where possible.
 *
 * Storage is still in-memory (per isolate). For multi-instance production,
 * replace the Map with Upstash Redis / Vercel KV and keep the same API.
 *
 * Limits:
 *   - 3 requests per IP per hour
 *   - 10 requests per IP per day
 *   - Soft global cap per isolate process (limits parallel Gemini burn on one instance)
 */

type Bucket = {
  hourWindowStart: number;
  hourCount: number;
  dayWindowStart: number;
  dayCount: number;
};

const store = new Map<string, Bucket>();

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_PER_HOUR = 3;
const MAX_PER_DAY = 10;

/** Per-isolate concurrent analyzes (best-effort, not cross-instance). */
let inFlight = 0;
const MAX_IN_FLIGHT = 3;

const HOUR_MS_GLOBAL = 60 * 60 * 1000;
let globalHourStart = Date.now();
let globalHourCount = 0;
const MAX_GLOBAL_PER_HOUR = 60; // per isolate — reduces blast radius if IP limit is bypassed

function now() {
  return Date.now();
}

export type RateLimitResult =
  | { allowed: true; release: () => void }
  | { allowed: false; retryAfterSeconds: number; reason: string };

export function checkRateLimit(ip: string): RateLimitResult {
  const t = now();

  // Global-ish budget on this isolate
  if (t - globalHourStart >= HOUR_MS_GLOBAL) {
    globalHourStart = t;
    globalHourCount = 0;
  }
  if (globalHourCount >= MAX_GLOBAL_PER_HOUR) {
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((HOUR_MS_GLOBAL - (t - globalHourStart)) / 1000),
      reason: "Service is busy. Please try again later.",
    };
  }

  if (inFlight >= MAX_IN_FLIGHT) {
    return {
      allowed: false,
      retryAfterSeconds: 30,
      reason: "Too many scans in progress. Please try again shortly.",
    };
  }

  const key = ip || "unknown";
  let b = store.get(key);

  if (!b) {
    b = {
      hourWindowStart: t,
      hourCount: 0,
      dayWindowStart: t,
      dayCount: 0,
    };
    store.set(key, b);
  }

  if (t - b.hourWindowStart >= HOUR_MS) {
    b.hourWindowStart = t;
    b.hourCount = 0;
  }
  if (t - b.dayWindowStart >= DAY_MS) {
    b.dayWindowStart = t;
    b.dayCount = 0;
  }

  if (b.hourCount >= MAX_PER_HOUR) {
    const retry = Math.ceil((HOUR_MS - (t - b.hourWindowStart)) / 1000);
    return {
      allowed: false,
      retryAfterSeconds: retry,
      reason: `Hourly limit reached (${MAX_PER_HOUR} scans per hour).`,
    };
  }

  if (b.dayCount >= MAX_PER_DAY) {
    const retry = Math.ceil((DAY_MS - (t - b.dayWindowStart)) / 1000);
    return {
      allowed: false,
      retryAfterSeconds: retry,
      reason: `Daily limit reached (${MAX_PER_DAY} scans per day).`,
    };
  }

  b.hourCount += 1;
  b.dayCount += 1;
  globalHourCount += 1;
  inFlight += 1;
  store.set(key, b);

  let released = false;
  const release = () => {
    if (!released) {
      released = true;
      inFlight = Math.max(0, inFlight - 1);
    }
  };

  return { allowed: true, release };
}

/**
 * Client IP for rate limiting.
 * Prefer Vercel-specific headers; do not trust the leftmost X-Forwarded-For
 * entry (that is often client-controlled).
 */
export function getClientIp(headers: Headers): string {
  const vercelFwd = headers.get("x-vercel-forwarded-for");
  if (vercelFwd) {
    const part = vercelFwd.split(",")[0]?.trim();
    if (part) return part;
  }

  const real = headers.get("x-real-ip")?.trim();
  if (real) return real;

  // Fallback: rightmost hop is typically added by the trusted proxy closest to us
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded) {
    const parts = forwarded.split(",").map((p) => p.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }

  return "unknown";
}
