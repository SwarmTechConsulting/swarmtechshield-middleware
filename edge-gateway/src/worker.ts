// SwarmTech Shield edge gateway for Cloudflare Workers.
// Screens every request at the edge and forwards only allowed ones to ORIGIN_URL.
// Configure in wrangler.toml (vars) and with `wrangler secret put` (secrets).
import { edgeGateway } from "@swarmtechshield/middleware";

interface Env {
  ORIGIN_URL: string;
  SHIELD_SYNC_URL: string;
  SHIELD_LOG_URL: string;
  SHIELD_CONNECTION_KEY: string;
  SHIELD_ORIGIN_SECRET?: string;
}

export default edgeGateway<Env>((env) => ({
  origin: env.ORIGIN_URL,
  originSecret: env.SHIELD_ORIGIN_SECRET,
  connectionKey: env.SHIELD_CONNECTION_KEY,
  syncUrl: env.SHIELD_SYNC_URL,
  logUrl: env.SHIELD_LOG_URL,
  // Paths that should fail closed while SwarmTech Shield is unreachable (the console's setting replaces this after the first sync).
  failClosedPaths: ["/login", "/checkout", "/admin"],
}));
