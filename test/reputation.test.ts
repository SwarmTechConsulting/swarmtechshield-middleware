import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { createClient } from "../src/client.ts";
import { matchRule } from "../src/engine.ts";
import { compileList, ThreatLists } from "../src/threatLists.ts";
import { startMock } from "./mock-server.ts";

test("matcher: v4, v6, mapped v4, overlaps; nothing wider than /8", () => {
  const m = compileList(["1.10.16.5/20", "1.10.16.0/24", "198.51.100.7", "2a06:e480::/29", "0.0.0.0/0", "::/0", "junk"]);
  assert.equal(m.size, 4);
  for (const ip of ["1.10.16.1", "1.10.31.255", "198.51.100.7", "::ffff:1.10.20.9", "2a06:e487:ffff::1"]) assert.ok(m.has(ip), ip);
  for (const ip of ["1.10.32.0", "8.8.8.8", "2a06:e488::", "", "x"]) assert.ok(!m.has(ip), ip);
});

test("engine: reputation rules match on lists, narrowed by method and path", () => {
  const rule = { type: "reputation", action: "block", criteria: { lists: ["tor"], path: "^/admin", method: "POST" } };
  assert.ok(matchRule(rule as never, { source_ip: "1.1.1.1", method: "POST", path: "/admin/x", threat_lists: ["tor"] }));
  assert.ok(!matchRule(rule as never, { source_ip: "1.1.1.1", method: "GET", path: "/admin/x", threat_lists: ["tor"] }));
  assert.ok(!matchRule(rule as never, { source_ip: "1.1.1.1", method: "POST", path: "/admin/x" }), "no lists: no match");
  assert.ok(!matchRule({ type: "reputation", criteria: {} } as never, { source_ip: "1.1.1.1", threat_lists: ["tor"] }));
});

test("lists arrive on sync only when out of date, and enforce reputation rules", async (t) => {
  const mock = await startMock({
    rules: [{ id: "r1", name: "Block Tor on admin", type: "reputation", action: "block", priority: 10, deployment_state: "enforced", criteria: { lists: ["tor"], path: "^/admin" } }],
  });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_reputation";
  mock.state.threatLists = { tor: { version: "v1", cidrs: ["185.220.101.0/24"] }, datacenter: { version: "d1", cidrs: ["3.0.0.0/8"] } };
  let now = Date.parse("2026-11-14T22:30:00Z");
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, now: () => now });
  assert.equal((await client.check({ ip: "185.220.101.9", path: "/admin/users" })).verdict, "blocked");
  assert.equal((await client.check({ ip: "185.220.101.9", path: "/shop" })).verdict, "allowed");
  assert.equal((await client.check({ ip: "198.51.100.1", path: "/admin" })).verdict, "allowed");
  assert.deepEqual(Object.keys(client.status().threatLists), ["tor"], "lists no rule uses are dropped");
  assert.deepEqual(mock.state.syncCalls[0].threat_list_versions, {}, "first sync holds nothing");
  // A later full sync reports the version held, so an unchanged list isn't sent again.
  mock.state.version = 2;
  now += 6 * 60_000;
  await (await client.check({ ip: "198.51.100.2", path: "/" })).background;
  const later = mock.state.syncCalls.at(-1)!;
  assert.equal(later.threat_list_versions?.tor, "v1");
});

test("ThreatLists ignores malformed payloads and keeps the same version without recompiling", () => {
  const t = new ThreatLists();
  t.apply({ "BAD KEY": { version: "1", cidrs: [] }, tor: { version: 7, cidrs: [] }, datacenter: "nope" });
  assert.equal(t.size, 0);
  t.apply({ tor: { version: "v1", cidrs: ["185.220.101.0/24"] } });
  t.apply({ tor: { version: "v1", cidrs: [] } });
  assert.deepEqual(t.listsFor("185.220.101.1"), ["tor"], "same version: kept");
});

test("matches Shield's matcher on the same inputs when both are checked out", async () => {
  const shield = new URL("../../swarmtech-shield/base44/shared/threatIntel.ts", import.meta.url);
  if (!existsSync(shield)) return;
  const { compileList: shieldCompile } = await import(shield.href);
  const cidrs = ["1.10.16.0/20", "198.51.100.7/32", "2a06:e480::/29", "34.1.208.0/20", "10.0.0.0/8"];
  const a = compileList(cidrs);
  const b = shieldCompile(cidrs);
  for (const ip of ["1.10.20.1", "1.10.32.1", "198.51.100.7", "2a06:e481::1", "34.1.223.255", "10.9.9.9", "11.0.0.0", "::ffff:198.51.100.7"]) {
    assert.equal(a.has(ip), b.has(ip), ip);
  }
});
