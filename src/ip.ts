// Client IP extraction.
//
// Getting the real client IP is the most security-sensitive part of the integration.
// Headers like X-Forwarded-For can be written by the client, so the first value must
// never be trusted. Each adapter picks a safe default for its platform; you can
// override it with `trustedHeader` or `trustedProxyCount`, or pass `getClientIp`.

import { ipMatches, parseIp } from "./engine.ts";

export interface IpOptions {
  /** Read the client IP from this single header (e.g. "cf-connecting-ip", "x-real-ip"). Only set this
   *  when your own infrastructure sets the header and strips any client-supplied value. */
  trustedHeader?: string;
  /** Number of proxies you run in front of the app that append to X-Forwarded-For. Default 1. */
  trustedProxyCount?: number;
}

type HeaderGetter = (name: string) => string | null | undefined;

/** Strip a port and brackets, validate. Returns "" when the value is not an IP address. */
export function cleanIp(value: string | null | undefined): string {
  if (!value) return "";
  let s = String(value).trim();
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end > 0) s = s.slice(1, end);
  } else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(s)) {
    s = s.slice(0, s.lastIndexOf(":"));
  }
  if (!parseIp(s)) return "";
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  return mapped ? mapped[1] : s;
}

/** The entry `trustedProxyCount` positions from the right of X-Forwarded-For. */
export function fromForwardedFor(xff: string | null | undefined, trustedProxyCount = 1): string {
  if (!xff) return "";
  const list = xff.split(",").map((s) => s.trim()).filter(Boolean);
  if (!list.length) return "";
  const count = Math.max(1, Math.floor(trustedProxyCount));
  const idx = Math.max(0, list.length - count);
  return cleanIp(list[idx]);
}

/**
 * Resolve the client IP from request headers.
 * Order: `trustedHeader` (if configured) → platform defaults given in `defaults` → X-Forwarded-For
 * counted from the right → `fallback` (e.g. the socket address).
 */
export function clientIpFromHeaders(
  get: HeaderGetter,
  opts: IpOptions = {},
  defaults: string[] = [],
  fallback?: string | null,
): string {
  if (opts.trustedHeader) {
    const v = get(opts.trustedHeader.toLowerCase());
    return cleanIp(v ? v.split(",")[0] : "");
  }
  for (const h of defaults) {
    const v = cleanIp((get(h) || "").split(",")[0]);
    if (v) return v;
  }
  const xff = fromForwardedFor(get("x-forwarded-for"), opts.trustedProxyCount ?? 1);
  if (xff) return xff;
  return cleanIp(fallback || "");
}

/* ---------------- where the IP came from ---------------- */

/**
 * How far the client IP can be trusted, reported to SwarmTech Shield on sync so
 * the console can warn about apps whose IPs could be spoofed:
 *  - platform:   set by the hosting platform, which overwrites client values (Vercel's
 *                x-real-ip, Cloudflare's CF-Connecting-IP).
 *  - configured: you chose the source (trustedHeader, trustedProxyCount, getClientIp,
 *                or Express's "trust proxy" setting).
 *  - socket:     the TCP peer address (Express without a proxy).
 *  - assumed:    a platform default this package can't verify (Base44's proxy).
 *  - none:       no trustworthy source, so the IP is left empty and IP rules can't apply.
 */
export type IpTrust = "platform" | "configured" | "socket" | "assumed" | "none";

export interface IpSource {
  method: string;
  trust: IpTrust;
  /** Set when the setup looks wrong; shown in the console and passed to onError once. */
  warning?: string;
}

const PRIVATE_RANGES = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"];

export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  return PRIVATE_RANGES.some((r) => {
    try {
      return ipMatches(ip, r);
    } catch {
      return false;
    }
  });
}

/** True when running on Vercel (its system environment variables are present). */
export function onVercel(): boolean {
  const env = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  return !!env && (env.VERCEL === "1" || !!env.VERCEL_ENV);
}

export const NO_TRUSTED_SOURCE =
  "Client IP can't be verified on this host, so IP blocks and per-IP limits are off. " +
  "Set trustedHeader to the header your proxy or platform sets (and overwrites), " +
  "trustedProxyCount for X-Forwarded-For, or getClientIp.";

export const BEHIND_PROXY =
  "Requests arrive from a private address with X-Forwarded-For set: the app looks to be behind a proxy, " +
  "so every visitor appears as the proxy's IP. Set trustedProxyCount (or Express's \"trust proxy\") so " +
  "blocks and limits apply to visitors, not the proxy.";
