"use client";

import { FormEvent, ReactNode, useMemo, useState } from "react";
import type { AnalyzeResponse } from "@/lib/types";

type Phase = "idle" | "scanning" | "writing" | "done" | "error";

function renderReport(markdownish: string) {
  // Lightweight rendering for ## headings and plain text from Gemini
  const blocks = markdownish.split("\n");
  const nodes: ReactNode[] = [];
  let buffer: string[] = [];

  const flush = () => {
    if (buffer.length) {
      nodes.push(
        <p key={`p-${nodes.length}`} style={{ margin: "0.4rem 0" }}>
          {buffer.join("\n")}
        </p>
      );
      buffer = [];
    }
  };

  for (const line of blocks) {
    if (line.startsWith("## ")) {
      flush();
      nodes.push(
        <h2 key={`h-${nodes.length}`}>{line.replace(/^##\s+/, "")}</h2>
      );
    } else if (line.startsWith("# ")) {
      flush();
      nodes.push(
        <h2 key={`h-${nodes.length}`}>{line.replace(/^#\s+/, "")}</h2>
      );
    } else if (line.trim() === "") {
      flush();
    } else {
      buffer.push(line);
    }
  }
  flush();
  return nodes;
}

export default function HomePage() {
  const [url, setUrl] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [summary, setSummary] = useState<AnalyzeResponse["scanSummary"] | null>(
    null
  );

  const statusText = useMemo(() => {
    if (phase === "scanning") return "Checking site configuration…";
    if (phase === "writing") return "Writing plain-language report…";
    return null;
  }, [phase]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setReport(null);
    setSummary(null);
    setPhase("scanning");

    // UX staging: we only have one API call, so flip label after a short delay
    const writeTimer = window.setTimeout(() => {
      setPhase((p) => (p === "scanning" ? "writing" : p));
    }, 2500);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = (await res.json()) as AnalyzeResponse;

      if (!res.ok || !data.ok) {
        const extra =
          data.retryAfterSeconds != null
            ? ` Try again in about ${Math.ceil(data.retryAfterSeconds / 60)} minute(s).`
            : "";
        throw new Error((data.error || "Request failed") + extra);
      }

      setReport(data.report || "");
      setSummary(data.scanSummary || null);
      setPhase("done");
    } catch (err) {
      setPhase("error");
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      window.clearTimeout(writeTimer);
    }
  }

  return (
    <main>
      <div className="brand">
        <div className="brand-mark" aria-hidden>
          SW
        </div>
        <h1>ScanWeasel</h1>
      </div>
      <p className="tagline">
        Passive website checks, explained in plain language.
      </p>

      <section className="card">
        <p className="disclaimer">
          <strong>Only scan sites you own or control.</strong> ScanWeasel runs
          limited passive checks (headers, CSP, cookies, HTTPS behaviour, a few
          public paths). It is not a penetration test and does not prove a site
          is secure.
        </p>

        <form onSubmit={onSubmit}>
          <input
            type="text"
            inputMode="url"
            placeholder="https://your-site.example"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            required
            disabled={phase === "scanning" || phase === "writing"}
            aria-label="Website URL"
          />
          <button
            type="submit"
            disabled={
              !url.trim() || phase === "scanning" || phase === "writing"
            }
          >
            {phase === "scanning" || phase === "writing" ? "Working…" : "Scan"}
          </button>
        </form>

        {statusText && (
          <div className="status" role="status" aria-live="polite">
            <span className="spinner" />
            {statusText}
          </div>
        )}

        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}

        {summary && phase === "done" && (
          <div className="summary">
            <span className="pill">
              Target: <strong>{summary.target}</strong>
            </span>
            <span className="pill">
              Signals noted: <strong>{summary.issueCount}</strong>
            </span>
            <span className="pill">
              Clean areas: <strong>{summary.cleanCount}</strong>
            </span>
            {summary.challengeSuspected && (
              <span className="pill">
                Bot-protection page may have influenced results
              </span>
            )}
          </div>
        )}

        {report && phase === "done" && (
          <article className="report">{renderReport(report)}</article>
        )}
      </section>

      <p className="footer">
        Rate limited to protect the service. Single-session results only — nothing
        is stored for sharing.
      </p>
    </main>
  );
}
