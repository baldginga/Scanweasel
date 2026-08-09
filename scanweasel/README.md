# ScanWeasel

Passive website security checks, explained in plain language.

ScanWeasel runs a **bounded** set of non-destructive checks (security headers, CSP heuristics, cookies, HTTPS redirect behaviour, CORS probe, and a small list of public paths), then uses **Gemini (Flash-class)** on the server to produce a natural-language **Strengths / Issues / What to do next** report.

> **Only scan sites you own or control.** This is not a penetration test.

## Stack

- Next.js (App Router)
- TypeScript scanner (`lib/scanner.ts`)
- Gemini via `@google/generative-ai` (`lib/gemini.ts`)
- Deploy on **Vercel**
- Strict IP rate limits (in-memory v1; swap to Upstash for multi-instance production)

## Setup

```bash
cd scanweasel
npm install
cp .env.example .env.local
# Edit .env.local and set GEMINI_API_KEY
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Environment

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | Yes | Google AI Studio API key |
| `GEMINI_MODEL` | No | Defaults to `gemini-2.0-flash` |
| `NEXT_PUBLIC_SITE_URL` | Recommended in prod | Public origin for CSRF allowlist |
| `REQUIRE_BROWSER_ORIGIN` | No | Set `1` to reject requests with no Origin/Referer |

## Deploy on Vercel

1. Push this folder to GitHub.
2. Import the repo in Vercel.
3. Add `GEMINI_API_KEY`, optional `GEMINI_MODEL`, and `NEXT_PUBLIC_SITE_URL=https://your-app.vercel.app`.
4. For a hostile environment (e.g. conference Wi‑Fi demo), also set `REQUIRE_BROWSER_ORIGIN=1`.
5. Deploy.

`maxDuration = 60` is set on the analyze route (effective on Pro; Hobby plans may enforce a lower cap).

## API

`POST /api/analyze`

```json
{ "url": "https://example.com" }
```

Success:

```json
{
  "ok": true,
  "report": "## Strengths\n...",
  "scanSummary": {
    "target": "https://example.com/",
    "issueCount": 2,
    "cleanCount": 4,
    "challengeSuspected": false
  }
}
```

Rate limited: **3 scans / IP / hour**, **10 / IP / day**, plus per-isolate concurrency and hourly budget.

## Security hardening (v1)

- **SSRF:** DNS resolution required; blocks loopback, RFC1918, link-local (incl. `169.254.169.254`), CGNAT, ULA, multicast; rejects off-domain redirects
- **CSRF:** same-origin `Origin` / `Referer` checks
- **Rate limit IP:** prefers `x-vercel-forwarded-for` / rightmost forwarded hop (not client-spoofable leftmost)
- **LLM:** sanitized payload only (no raw target CSP/header values)
- **Errors:** generic client messages; details in server logs
- **Headers:** CSP, `frame-ancestors 'none'`, `X-Frame-Options`, etc. via `next.config.ts`

## What v1 checks

- Security headers (CSP, HSTS, X-Frame-Options, …)
- CSP weak-pattern heuristics
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- HTTP → HTTPS behaviour
- Simple CORS probe
- Paths: `robots.txt`, `sitemap.xml`, `.well-known/security.txt`, `security.txt`, `.env`, `.git/HEAD`, `package.json`, `wp-login.php`, `admin/`

## Not in v1

- Full harness_v3 path lists / stealth delays
- Shareable report links
- Accounts / ownership verification
- Background job queues
- Shared Redis rate limits (still in-memory per isolate)

## License

Use for legitimate testing of systems you own or are authorised to test.
