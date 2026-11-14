import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient } from "../src/client.ts";
import { normaliseFailClosedPaths, pathFailsClosed } from "../src/failMode.ts";
import { startMock } from "./mock-server.ts";

test("path matching: prefixes on segment boundaries, wildcards, case and query ignored", () => {
  const p = normaliseFailClosedPaths(["/Login", "api/pay*", "/admin/", "/login", "  ", "/a b", 42]);
  assert.deepEqual(p, ["/login", "/api/pay*", "/admin", "/42"]);
  for (const ok of ["/login", "/LOGIN/step2", "/login?next=/", "/api/payments", "/api/pay", "/admin", "/admin/users"]) assert.ok(pathFailsClosed(ok, p), ok);
  for (const no of ["/loginx", "/", "/api/pa", "/administrator", "/public/login"]) assert.ok(!pathFailsClosed(no, p), no);
  assert.ok(pathFailsClosed("/anything", ["/"]));
  assert.equal(normaliseFailClosedPaths(Array.from({ length: 30 }, (_, i) => `/p${i}`)).length, 20);
});

test("before any rules load: listed paths fail closed, the rest fail open", async () => {
  const client = createClient({
    connectionKey: "sts_conn_failmode",
    syncUrl: "http://127.0.0.1:9/unreachable",
    failClosedPaths: ["/login", "/checkout"],
    firstSyncTimeoutMs: 50,
    requestTimeoutMs: 50,
  });
  const login = await client.check({ ip: "198.51.100.1", path: "/login" });
  assert.equal(login.verdict, "blocked");
  assert.equal(login.source, "fail_closed");
  const home = await client.check({ ip: "198.51.100.1", path: "/" });
  assert.equal(home.verdict, "allowed");
  assert.equal(home.source, "fail_open");
});

test("the app's list from sync replaces the local one and applies when rules go stale", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_failmode_sync";
  mock.state.failClosedPaths = ["/admin"];
  let now = Date.parse("2026-11-14T10:00:00Z");
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, now: () => now, failClosedPaths: ["/login"], maxStaleMs: 60_000 });
  assert.equal((await client.check({ ip: "198.51.100.2", path: "/admin" })).verdict, "allowed", "rules loaded: screened normally");
  assert.deepEqual(client.status().failClosedPaths, ["/admin"]);
  mock.state.syncStatus = 503;
  now += 120_000;
  const admin = await client.check({ ip: "198.51.100.2", path: "/admin/users" });
  assert.equal(admin.source, "fail_closed");
  assert.equal((await client.check({ ip: "198.51.100.2", path: "/login" })).source, "fail_open", "the server's list replaced the local one");
});
