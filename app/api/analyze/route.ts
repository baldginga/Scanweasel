import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scanner";
import { explainScan } from "@/lib/gemini";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { assertSafeScanTarget } from "@/lib/url-safety";
import type { AnalyzeResponse } from "@/lib/types";

export const runtime = "nodejs";
export const maxDuration = 60;

const MAX_URL_LENGTH = 2048;

function allowedOrigins(): Set<string> {
  const set = new Set<string>();
  const site = process.env.NEXT_PUBLIC_SITE_URL || process.env.VERCEL_URL;
  if (site) {
    try {
      const u = site.startsWith("http") ? site : `https://${site}`;
      set.add(new URL(u).origin);
    } catch {
      /* ignore */
    }
  }
  set.add("http://localhost:3000");
  set.add("http://127.0.0.1:3000");
  return set;
}

/**
 * Reject cross-site browser POSTs (CSRF / drive-by Gemini burn).
 * Allows same-origin. Non-browser clients that omit Origin are allowed
 * unless REQUIRE_BROWSER_ORIGIN=1.
 */
function assertSameOrigin(req: NextRequest): void {
  const origin = req.headers.get("origin");
  const referer = req.headers.get("referer");
  const allowed = allowedOrigins();

  try {
    allowed.add(req.nextUrl.origin);
  } catch {
    /* ignore */
  }

  if (origin) {
    if (!allowed.has(origin)) {
      throw new Error("csrf");
    }
    return;
  }

  if (referer) {
    try {
      const refOrigin = new URL(referer).origin;
      if (!allowed.has(refOrigin)) {
        throw new Error("csrf");
      }
      return;
    } catch {
      throw new Error("csrf");
    }
  }

  if (process.env.REQUIRE_BROWSER_ORIGIN === "1") {
    throw new Error("csrf");
  }
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req.headers);
  const limited = checkRateLimit(ip);

  if (!limited.allowed) {
    const body: AnalyzeResponse = {
      ok: false,
      error: limited.reason,
      retryAfterSeconds: limited.retryAfterSeconds,
    };
    return NextResponse.json(body, {
      status: 429,
      headers: { "Retry-After": String(limited.retryAfterSeconds) },
    });
  }

  const release = limited.release;

  try {
    try {
      assertSameOrigin(req);
    } catch {
      return NextResponse.json(
        { ok: false, error: "Request not allowed from this origin." } satisfies AnalyzeResponse,
        { status: 403 }
      );
    }

    let url: string;
    try {
      const json = await req.json();
      url = typeof json?.url === "string" ? json.url.trim() : "";
    } catch {
      return NextResponse.json(
        { ok: false, error: "Expected JSON body with a url string." } satisfies AnalyzeResponse,
        { status: 400 }
      );
    }

    if (!url || url.length > MAX_URL_LENGTH) {
      return NextResponse.json(
        { ok: false, error: "Please provide a valid public website URL." } satisfies AnalyzeResponse,
        { status: 400 }
      );
    }

    try {
      await assertSafeScanTarget(url);
    } catch {
      return NextResponse.json(
        {
          ok: false,
          error:
            "That URL cannot be scanned. Use a public http(s) website you own or control.",
        } satisfies AnalyzeResponse,
        { status: 400 }
      );
    }

    try {
      const scan = await runScan(url);
      const report = await explainScan(scan);

      const body: AnalyzeResponse = {
        ok: true,
        report,
        scanSummary: {
          target: scan.target,
          issueCount: scan.issues.length,
          cleanCount: scan.cleanAreas.length,
          challengeSuspected: scan.headers.challengeSuspected,
        },
      };
      return NextResponse.json(body);
    } catch (e) {
      console.error("analyze error:", e instanceof Error ? e.message : e);
      return NextResponse.json(
        {
          ok: false,
          error: "Scan failed. Please try again later or check the URL.",
        } satisfies AnalyzeResponse,
        { status: 500 }
      );
    }
  } finally {
    release();
  }
}
