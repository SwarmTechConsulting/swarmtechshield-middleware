// Edge gateway: SwarmTech Shield as a reverse proxy on Cloudflare Workers.
//
// The Worker sits in front of your app (on your domain's route), screens every
// request at the edge with the cached rules this package keeps in memory, and
// forwards only allowed requests to your origin. Nothing in your app changes,
// and screening never calls SwarmTech Shield per request: the Worker syncs rules
// in the background and uploads logs in batches.
//
//   import { edgeGateway } from "@swarmtechshield/middleware";
//   export default edgeGateway((env) => ({
//     origin: env.ORIGIN_URL,                 // e.g. "https://origin.example.com"
//     originSecret: env.SHIELD_ORIGIN_SECRET,  // sent as x-shield-edge, so the origin can refuse bypass
//     connectionKey: env.SHIELD_CONNECTION_KEY,
//     syncUrl: env.SHIELD_SYNC_URL,
//     logUrl: env.SHIELD_LOG_URL,
//   }));
//
// What it does for each request:
//  1. Drops any x-shield-edge header the visitor sent (only the Worker may set it).
//  2. Screens it (the same engine, inspection, decoys and defences as the other adapters;
//     the client IP is CF-Connecting-IP, which Cloudflare sets).
//  3. Answers blocked, throttled, shed and decoy requests itself.
//  4. Forwards the rest to the origin with X-Forwarded-For/-Host/-Proto, the
//     origin secret, and the original method, headers and body. Redirects from
//     the origin are passed back to the visitor, never followed.
//  5. Reports the origin's status for response signals (404 and 401/403 floods,
//     5xx spikes), and answers 502 or 504 if the origin can't be reached.

import { cloudflare, type FetchAdapterOptions, type WaitUntilContext } from "./fetch.ts";
import { decorate, toResponse } from "./shared.ts";

export const EDGE_HEADER = "x-shield-edge";

export interface EdgeOptions extends FetchAdapterOptions {
  /** The origin to forward allowed requests to, e.g. "https://origin.example.com" (a path prefix is kept). */
  origin: string;
  /** Sent to the origin as `x-shield-edge` (or `originHeader`), so it can refuse requests that didn't come through the gateway. */
  originSecret?: string;
  /** Header name for the origin secret. Default x-shield-edge. */
  originHeader?: string;
  /** Send the visitor's Host header to the origin instead of the origin's own. Default false. */
  preserveHost?: boolean;
  /** Give up on the origin after this long and answer 504. Default 30 s. */
  originTimeoutMs?: number;
}

export type EdgeConfig<Env> = EdgeOptions | ((env: Env) => EdgeOptions);

// Hop-by-hop headers are never forwarded (RFC 9110 §7.6.1).
const HOP_BY_HOP = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding"];

/** Checks the origin URL. Returns the parsed URL or a reason it can't be used. */
export function parseOrigin(origin: string): URL | string {
  let u: URL;
  try {
    u = new URL(String(origin || ""));
  } catch {
    return "origin must be an absolute URL such as https://origin.example.com";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return "origin must use https (or http)";
  if (u.search || u.hash) return "origin must not have a query string or fragment";
  if (u.username || u.password) return "origin must not carry credentials";
  return u;
}

/** The URL to fetch at the origin for a visitor's request. */
export function originUrl(origin: URL, requestUrl: string): string {
  const req = new URL(requestUrl);
  const base = origin.pathname.replace(/\/+$/, "");
  return `${origin.protocol}//${origin.host}${base}${req.pathname}${req.search}`;
}

/** The headers to send to the origin. */
export function originHeaders(request: Request, opts: EdgeOptions, origin: URL): Headers {
  const h = new Headers(request.headers);
  const secretHeader = (opts.originHeader || EDGE_HEADER).toLowerCase();
  h.delete(secretHeader);
  h.delete(EDGE_HEADER);
  for (const name of HOP_BY_HOP) h.delete(name);
  const visitor = new URL(request.url);
  const ip = request.headers.get("cf-connecting-ip") || "";
  if (ip) {
    const prior = request.headers.get("x-forwarded-for");
    h.set("x-forwarded-for", prior ? `${prior}, ${ip}` : ip);
    h.set("x-real-ip", ip);
  }
  h.set("x-forwarded-host", visitor.host);
  h.set("x-forwarded-proto", visitor.protocol.replace(":", ""));
  if (opts.preserveHost) h.set("host", visitor.host);
  else h.set("host", origin.host);
  if (opts.originSecret) h.set(secretHeader, opts.originSecret);
  return h;
}

function plain(status: number, text: string): Response {
  return new Response(text, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
}

let reportedConfig = "";

/**
 * A Cloudflare Workers handler (`export default edgeGateway(...)`). The config can
 * be a function of the Worker's env, where secrets live.
 */
export function edgeGateway<Env = Record<string, string>>(config: EdgeConfig<Env>) {
  return {
    async fetch(request: Request, env: Env, ctx?: WaitUntilContext): Promise<Response> {
      let opts: EdgeOptions;
      try {
        opts = typeof config === "function" ? config(env) : config;
      } catch (err) {
        console.error(`[swarmtechshield] edge gateway config failed: ${(err as Error).message}`);
        return plain(500, "Gateway misconfigured");
      }
      const origin = parseOrigin(opts?.origin);
      if (typeof origin === "string" || new URL(request.url).host === origin.host) {
        const why = typeof origin === "string" ? origin : "origin is this gateway's own host, which would loop";
        if (reportedConfig !== why) {
          reportedConfig = why;
          const e = new Error(`Edge gateway: ${why}`);
          if (opts?.onError) opts.onError(e, "config");
          else console.error(`[swarmtechshield] ${e.message}`);
        }
        return plain(500, "Gateway misconfigured");
      }

      // Only the gateway may set the origin secret header.
      const secretHeader = (opts.originHeader || EDGE_HEADER).toLowerCase();
      let screened = request;
      if (request.headers.has(secretHeader) || request.headers.has(EDGE_HEADER)) {
        const h = new Headers(request.headers);
        h.delete(secretHeader);
        h.delete(EDGE_HEADER);
        screened = new Request(request, { headers: h });
      }

      const result = await cloudflare(screened, opts, ctx);
      const refusal = toResponse(result, opts);
      if (refusal) return refusal;

      const method = screened.method.toUpperCase();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.originTimeoutMs ?? 30_000);
      let upstream: Response;
      try {
        upstream = await fetch(originUrl(origin, screened.url), {
          method,
          headers: originHeaders(screened, opts, origin),
          body: method === "GET" || method === "HEAD" ? undefined : screened.body,
          redirect: "manual",
          signal: controller.signal,
          // Streams the body through (needed by fetch implementations that follow the spec strictly).
          ...(method === "GET" || method === "HEAD" ? {} : { duplex: "half" }),
        } as RequestInit);
      } catch (err) {
        const timedOut = (err as Error)?.name === "AbortError";
        result.reportResponse?.(timedOut ? 504 : 502);
        return plain(timedOut ? 504 : 502, timedOut ? "Gateway Timeout" : "Bad Gateway");
      } finally {
        clearTimeout(timer);
      }
      result.reportResponse?.(upstream.status);
      // WebSocket upgrades and other special responses pass through untouched.
      if (upstream.status === 101 || !result.verification) return upstream;
      return decorate(upstream, result);
    },
  };
}
