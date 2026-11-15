// Response-side signals: what the app answered says things the request alone can't.
//
//  - Not-found floods from one IP (forced browsing, directory and API enumeration):
//    by default 40 "404 Not Found" responses in 60 s blocks the IP on this server.
//  - Auth-failure floods from one IP (token guessing, broken-access probing): by
//    default 25 responses of 401 or 403 in 60 s throttles the IP.
//  - Server-error spikes across the app (an outage, or a request that crashes the
//    app being repeated): by default 50 responses of 5xx in 60 s logs one incident.
//    Nothing is blocked for this.
//
// The middleware learns the status from your framework (Express does it on its
// own) or from result.reportResponse(status). Static assets (images, fonts,
// scripts, styles, source maps, favicon) never count, so a missing icon can't
// get a visitor blocked.
//
// Runtime-agnostic, in memory, per server.

import { compileLinear, type LinearRegex } from "./linearRegex.ts";

export type SignalAction = "block" | "throttle" | "log";

export interface SignalThreshold {
  count: number;
  windowSeconds: number;
  action?: SignalAction;
}

export interface ResponseSignalOptions {
  /** 404 responses per IP. Default { count: 40, windowSeconds: 60, action: "block" }. false turns it off. */
  notFound?: SignalThreshold | false;
  /** 401 and 403 responses per IP. Default { count: 25, windowSeconds: 60, action: "throttle" }. false turns it off. */
  authFailures?: SignalThreshold | false;
  /** 5xx responses across the app (logged, never blocks). Default { count: 50, windowSeconds: 60 }. false turns it off. */
  serverErrors?: Omit<SignalThreshold, "action"> | false;
  /** Paths that never count (patterns). Default: static assets. */
  ignorePaths?: string[];
}

export type SignalType = "not_found" | "auth_failures" | "server_errors";

export interface ResponseSignal {
  type: SignalType;
  /** The IP for per-IP signals; "" for app-wide ones. */
  ip: string;
  action: SignalAction;
  count: number;
  windowSeconds: number;
  reason: string;
}

export const STATIC_ASSETS = "\\.(ico|png|jpe?g|gif|svg|webp|avif|css|js|mjs|map|woff2?|ttf|eot)(\\?|$)";
const MAX_IPS = 10_000;
/** After a signal fires for an IP, don't report the same signal for it again for this long. */
const REPEAT_MS = 10 * 60_000;

const DEFAULTS = {
  notFound: { count: 40, windowSeconds: 60, action: "block" as SignalAction },
  authFailures: { count: 25, windowSeconds: 60, action: "throttle" as SignalAction },
  serverErrors: { count: 50, windowSeconds: 60 },
};

function threshold<T extends { count: number; windowSeconds: number }>(given: T | false | undefined, fallback: T): T | null {
  if (given === false) return null;
  if (!given) return fallback;
  const count = Math.max(2, Math.floor(Number(given.count) || fallback.count));
  const windowSeconds = Math.max(5, Math.min(3600, Math.floor(Number(given.windowSeconds) || fallback.windowSeconds)));
  return { ...fallback, ...given, count, windowSeconds };
}

export class ResponseSignals {
  readonly notFound: (SignalThreshold & { action: SignalAction }) | null;
  readonly authFailures: (SignalThreshold & { action: SignalAction }) | null;
  readonly serverErrors: Omit<SignalThreshold, "action"> | null;
  private ignore: LinearRegex[] = [];
  private perIp = new Map<string, { notFound: number[]; auth: number[]; firedNotFound?: number; firedAuth?: number }>();
  private errors: number[] = [];
  private firedErrors = 0;
  /** Signals fired so far, by type. */
  readonly fired: Record<SignalType, number> = { not_found: 0, auth_failures: 0, server_errors: 0 };

  constructor(options: ResponseSignalOptions = {}) {
    this.notFound = threshold(options.notFound, DEFAULTS.notFound) as never;
    this.authFailures = threshold(options.authFailures, DEFAULTS.authFailures) as never;
    this.serverErrors = threshold(options.serverErrors, DEFAULTS.serverErrors);
    for (const p of options.ignorePaths ?? [STATIC_ASSETS]) {
      try {
        this.ignore.push(compileLinear(p));
      } catch {
        // an unusable pattern is skipped
      }
    }
  }

  private ignored(path: string): boolean {
    return this.ignore.some((re) => re.test(path));
  }

  /**
   * Records one response. Returns the signals this response tipped over (at most
   * one per IP signal, plus the app-wide one), or an empty list.
   */
  record(ip: string, path: string, status: number, now: number): ResponseSignal[] {
    const out: ResponseSignal[] = [];
    if (!Number.isFinite(status) || status < 100) return out;
    if (this.ignored(path || "/")) return out;

    if (status >= 500 && this.serverErrors) {
      const t = this.serverErrors;
      this.errors = prune(this.errors, now - t.windowSeconds * 1000);
      this.errors.push(now);
      if (this.errors.length >= t.count && now - this.firedErrors > REPEAT_MS) {
        this.firedErrors = now;
        this.fired.server_errors++;
        out.push({ type: "server_errors", ip: "", action: "log", count: this.errors.length, windowSeconds: t.windowSeconds, reason: `Server errors: ${this.errors.length} responses of 5xx across the app in ${t.windowSeconds}s` });
      }
    }

    const isNotFound = status === 404 && this.notFound;
    const isAuth = (status === 401 || status === 403) && this.authFailures;
    if (!ip || (!isNotFound && !isAuth)) return out;

    let s = this.perIp.get(ip);
    if (!s) {
      if (this.perIp.size >= MAX_IPS) this.evict(now);
      s = { notFound: [], auth: [] };
      this.perIp.set(ip, s);
    }
    if (isNotFound) {
      const t = this.notFound!;
      s.notFound = prune(s.notFound, now - t.windowSeconds * 1000);
      s.notFound.push(now);
      if (s.notFound.length >= t.count && !(s.firedNotFound && now - s.firedNotFound < REPEAT_MS)) {
        s.firedNotFound = now;
        this.fired.not_found++;
        out.push({ type: "not_found", ip, action: t.action, count: s.notFound.length, windowSeconds: t.windowSeconds, reason: `Response signals: ${s.notFound.length} not-found responses in ${t.windowSeconds}s (forced browsing or enumeration)` });
      }
    } else if (isAuth) {
      const t = this.authFailures!;
      s.auth = prune(s.auth, now - t.windowSeconds * 1000);
      s.auth.push(now);
      if (s.auth.length >= t.count && !(s.firedAuth && now - s.firedAuth < REPEAT_MS)) {
        s.firedAuth = now;
        this.fired.auth_failures++;
        out.push({ type: "auth_failures", ip, action: t.action, count: s.auth.length, windowSeconds: t.windowSeconds, reason: `Response signals: ${s.auth.length} unauthorised or forbidden responses in ${t.windowSeconds}s` });
      }
    }
    return out;
  }

  /** Drops IPs with nothing recent. */
  evict(now: number) {
    const horizon = now - Math.max(this.notFound?.windowSeconds ?? 0, this.authFailures?.windowSeconds ?? 0, 60) * 1000;
    for (const [ip, s] of this.perIp) {
      const last = Math.max(s.notFound.at(-1) ?? 0, s.auth.at(-1) ?? 0);
      if (last < horizon && !(s.firedNotFound && now - s.firedNotFound < REPEAT_MS) && !(s.firedAuth && now - s.firedAuth < REPEAT_MS)) this.perIp.delete(ip);
    }
    // Still full of active IPs: drop the oldest entries.
    while (this.perIp.size >= MAX_IPS) {
      const first = this.perIp.keys().next().value;
      if (first === undefined) break;
      this.perIp.delete(first);
    }
  }

  state() {
    return {
      notFound: this.notFound,
      authFailures: this.authFailures,
      serverErrors: this.serverErrors,
      trackedIps: this.perIp.size,
      fired: { ...this.fired },
    };
  }
}

function prune(list: number[], since: number): number[] {
  let i = 0;
  while (i < list.length && list[i] < since) i++;
  return i ? list.slice(i) : list;
}
