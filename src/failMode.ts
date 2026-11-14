// Per-route fail mode: which paths fail closed when rules can't be used.
//
// The app's fail mode (open by default) decides what happens when SwarmTech
// Shield can't be reached and no usable rules are cached. Most routes should
// stay up (fail open), but a few are worth refusing rather than serving
// unprotected: login, payment, admin. Those are listed as fail-closed paths.
//
// Matching, the same in SwarmTech Shield (base44/shared/failMode.ts):
//  - case-insensitive, on the path without its query string;
//  - "/login" matches "/login" and "/login/..." but not "/loginx";
//  - a trailing "*" matches any continuation: "/api/pay*" matches "/api/payments";
//  - "/" matches everything.

export const MAX_FAIL_CLOSED_PATHS = 20;

/** Clean a list of path prefixes: leading "/", lowercase, no query, no duplicates. */
export function normaliseFailClosedPaths(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const item of raw) {
    let p = String(item ?? "").trim().toLowerCase().split("?")[0].split("#")[0];
    if (!p) continue;
    if (!p.startsWith("/")) p = "/" + p;
    if (p.length > 1 && p.endsWith("/") && !p.endsWith("*")) p = p.replace(/\/+$/, "") || "/";
    if (p.length > 200 || /\s/.test(p)) continue;
    if (!out.includes(p)) out.push(p);
    if (out.length >= MAX_FAIL_CLOSED_PATHS) break;
  }
  return out;
}

export function pathFailsClosed(path: string, prefixes: string[]): boolean {
  if (!prefixes.length) return false;
  const p = String(path || "/").split("?")[0].toLowerCase() || "/";
  for (const prefix of prefixes) {
    if (prefix === "/") return true;
    if (prefix.endsWith("*")) {
      if (p.startsWith(prefix.slice(0, -1))) return true;
    } else if (p === prefix || p.startsWith(prefix + "/")) {
      return true;
    }
  }
  return false;
}
