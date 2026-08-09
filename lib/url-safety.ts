/**
 * URL / SSRF guards for outbound scan fetches.
 * Best-effort: block private, loopback, link-local, metadata, and non-global IPs
 * after DNS resolution. Not a substitute for an egress proxy allowlist.
 */

import dns from "dns/promises";
import net from "net";

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.google",
  "kubernetes.default",
  "kubernetes.default.svc",
]);

/** Return true if the IP must not be contacted by the scanner. */
export function isBlockedIp(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();
  if (!normalized) return true;

  if (net.isIP(normalized) === 4) {
    const parts = normalized.split(".").map((p) => Number(p));
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b] = parts;

    // 0.0.0.0/8, 127.0.0.0/8 loopback
    if (a === 0 || a === 127) return true;
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 link-local (includes cloud metadata 169.254.169.254)
    if (a === 169 && b === 254) return true;
    // 100.64.0.0/10 CGNAT
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 docs/test
    if (a === 192 && b === 0) return true;
    if (a === 198 && (b === 18 || b === 19 || b === 51)) return true;
    if (a === 203 && b === 0) return true;
    // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved
    if (a >= 224) return true;

    return false;
  }

  if (net.isIP(normalized) === 6) {
    // Strip zone id if present (fe80::1%eth0)
    const core = normalized.split("%")[0];
    // Loopback
    if (core === "::1") return true;
    // Unspecified
    if (core === "::") return true;
    // IPv4-mapped :ffff:x.x.x.x
    const v4mapped = core.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (v4mapped) return isBlockedIp(v4mapped[1]);
    // Link-local fe80::/10
    if (/^fe[89ab][0-9a-f]:/i.test(core)) return true;
    // Unique local fc00::/7
    if (/^f[cd][0-9a-f]{2}:/i.test(core)) return true;
    // Multicast ff00::/8
    if (/^ff[0-9a-f]{2}:/i.test(core)) return true;

    return false;
  }

  // Not a parseable IP
  return true;
}

function looksLikeBlockedHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (BLOCKED_HOSTNAMES.has(h)) return true;
  if (h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) {
    return true;
  }
  if (h.endsWith(".localdomain")) return true;
  // AWS / cloud metadata hostnames sometimes used
  if (h.includes("metadata") && h.includes("internal")) return true;
  return false;
}

/**
 * Validate user input URL string for scanning.
 * Resolves DNS and ensures all addresses are publicly routable.
 */
export async function assertSafeScanTarget(rawInput: string): Promise<string> {
  let withProto = rawInput.trim();
  if (!/^https?:\/\//i.test(withProto)) {
    withProto = "https://" + withProto;
  }

  let parsed: URL;
  try {
    parsed = new URL(withProto);
  } catch {
    throw new Error("Invalid URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https URLs are allowed");
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (!hostname) {
    throw new Error("Invalid hostname");
  }

  if (hostname.length > 253) {
    throw new Error("Hostname too long");
  }

  if (looksLikeBlockedHostname(hostname)) {
    throw new Error("That host is not allowed");
  }

  // Literal IP in the URL
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new Error("That address is not allowed");
    }
  } else {
    // Resolve A/AAAA — reject if any answer is non-public
    let records: { address: string; family: number }[] = [];
    try {
      records = await dns.lookup(hostname, { all: true, verbatim: true });
    } catch {
      throw new Error("Could not resolve hostname");
    }
    if (!records.length) {
      throw new Error("Could not resolve hostname");
    }
    for (const r of records) {
      if (isBlockedIp(r.address)) {
        throw new Error("Hostname resolves to a non-public address");
      }
    }
  }

  // Canonical scan origin (https, host only, trailing slash)
  return `https://${hostname}/`;
}

/** Ensure a redirect target stays on an allowed public host (same rules). */
export async function assertSafeFetchUrl(urlStr: string, expectedHost?: string): Promise<void> {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error("Invalid fetch URL");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Invalid fetch protocol");
  }
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (expectedHost && host.toLowerCase() !== expectedHost.toLowerCase()) {
    throw new Error("Redirect left the original host");
  }
  if (looksLikeBlockedHostname(host)) {
    throw new Error("Blocked host");
  }
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new Error("Blocked address");
  } else {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    for (const r of records) {
      if (isBlockedIp(r.address)) {
        throw new Error("Redirect host resolves to a non-public address");
      }
    }
  }
}
