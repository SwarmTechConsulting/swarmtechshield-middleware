// Platform threat lists for "reputation" rules (Spamhaus DROP, Tor exit relays,
// cloud and hosting providers). SwarmTech Shield refreshes them every 6 hours
// and sends a list in the sync response only when one of the app's rules uses
// it and this client's copy is out of date (it reports the versions it holds).
// Matching is the same as Shield's (base44/shared/threatIntel.ts): CIDRs are
// validated (nothing wider than a /8), merged, and searched by bisection.

export interface ThreatListPayload {
  version: string;
  cidrs: string[];
}

function v4ToInt(s: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function v6ToBig(s: string): bigint | null {
  if (!/^[0-9a-f:]+$/i.test(s) || s.length > 39) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  let n = BigInt(0);
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << BigInt(16)) + BigInt(parseInt(g, 16));
  }
  return n;
}

export interface ListMatcher {
  size: number;
  has(ip: string): boolean;
}

export function compileList(cidrs: string[]): ListMatcher {
  const v4: [number, number][] = [];
  const v6: [bigint, bigint][] = [];
  let size = 0;
  for (const raw of cidrs) {
    const [addr, bitsRaw, extra] = String(raw || "").trim().toLowerCase().split("/");
    if (extra !== undefined || !addr) continue;
    if (addr.includes(":")) {
      const n = v6ToBig(addr);
      const bits = bitsRaw === undefined ? 128 : Number(bitsRaw);
      if (n === null || !Number.isInteger(bits) || bits < 8 || bits > 128) continue;
      const host = BigInt(128 - bits);
      const start = (n >> host) << host;
      v6.push([start, start + (BigInt(1) << host) - BigInt(1)]);
    } else {
      const n = v4ToInt(addr);
      const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
      if (n === null || !Number.isInteger(bits) || bits < 8 || bits > 32) continue;
      const span = 2 ** (32 - bits);
      const start = Math.floor(n / span) * span;
      v4.push([start, start + span - 1]);
    }
    size++;
  }
  const r4 = mergeNum(v4);
  const r6 = mergeBig(v6);
  return {
    size,
    has(ip: string): boolean {
      const s = String(ip || "").trim().toLowerCase();
      if (!s) return false;
      const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
      if (mapped || !s.includes(":")) {
        const n = v4ToInt(mapped ? mapped[1] : s);
        return n !== null && findNum(r4, n);
      }
      const n = v6ToBig(s.split("%")[0]);
      return n !== null && findBig(r6, n);
    },
  };
}

function mergeNum(rs: [number, number][]): [number, number][] {
  rs.sort((a, b) => a[0] - b[0]);
  const out: [number, number][] = [];
  for (const r of rs) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push([r[0], r[1]]);
  }
  return out;
}

function mergeBig(rs: [bigint, bigint][]): [bigint, bigint][] {
  rs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const out: [bigint, bigint][] = [];
  for (const r of rs) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + BigInt(1)) {
      if (r[1] > last[1]) last[1] = r[1];
    } else out.push([r[0], r[1]]);
  }
  return out;
}

function findNum(rs: [number, number][], x: number): boolean {
  let lo = 0;
  let hi = rs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (x < rs[mid][0]) hi = mid - 1;
    else if (x > rs[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

function findBig(rs: [bigint, bigint][], x: bigint): boolean {
  let lo = 0;
  let hi = rs.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (x < rs[mid][0]) hi = mid - 1;
    else if (x > rs[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

const KEY = /^[a-z0-9_]{1,40}$/;

/** The lists this client holds. */
export class ThreatLists {
  private lists = new Map<string, { version: string; matcher: ListMatcher }>();

  /** Apply lists from a sync response; a list with the same version is skipped. */
  apply(payload: unknown): void {
    if (!payload || typeof payload !== "object") return;
    for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
      if (!KEY.test(key) || !value || typeof value !== "object") continue;
      const v = value as Partial<ThreatListPayload>;
      if (typeof v.version !== "string" || !Array.isArray(v.cidrs)) continue;
      if (this.lists.get(key)?.version === v.version) continue;
      this.lists.set(key, { version: v.version.slice(0, 80), matcher: compileList(v.cidrs.slice(0, 200_000)) });
    }
  }

  /** Drop lists no rule uses any more. */
  retain(keys: string[]): void {
    for (const k of [...this.lists.keys()]) if (!keys.includes(k)) this.lists.delete(k);
  }

  versions(): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of this.lists) out[k] = v.version;
    return out;
  }

  get size(): number {
    return this.lists.size;
  }

  /** Which lists an IP is on. */
  listsFor(ip: string): string[] {
    if (!ip || !this.lists.size) return [];
    const out: string[] = [];
    for (const [k, v] of this.lists) if (v.matcher.has(ip)) out.push(k);
    return out;
  }

  status(): Record<string, { version: string; ranges: number }> {
    const out: Record<string, { version: string; ranges: number }> = {};
    for (const [k, v] of this.lists) out[k] = { version: v.version, ranges: v.matcher.size };
    return out;
  }
}
