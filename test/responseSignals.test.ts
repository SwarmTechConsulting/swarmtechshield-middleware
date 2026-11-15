import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient } from "../src/client.ts";
import { ResponseSignals } from "../src/responses.ts";
import { express } from "../src/adapters/express.ts";
import { startMock } from "./mock-server.ts";

const T0 = Date.parse("2026-11-15T09:00:00Z");

test("a 404 flood from one IP fires once, then stays quiet", () => {
  const s = new ResponseSignals();
  let fired: ReturnType<ResponseSignals["record"]> = [];
  for (let i = 0; i < 39; i++) assert.deepEqual(s.record("203.0.113.9", `/admin${i}.php`, 404, T0 + i * 100), []);
  fired = s.record("203.0.113.9", "/wp-admin/", 404, T0 + 4000);
  assert.equal(fired.length, 1);
  assert.deepEqual([fired[0].type, fired[0].action, fired[0].count], ["not_found", "block", 40]);
  assert.deepEqual(s.record("203.0.113.9", "/x", 404, T0 + 4100), [], "not reported again straight away");
  assert.deepEqual(s.record("198.51.100.1", "/x", 404, T0 + 4100), [], "other IPs have their own counts");
});

test("404s spread over a longer time don't count", () => {
  const s = new ResponseSignals();
  for (let i = 0; i < 100; i++) assert.deepEqual(s.record("203.0.113.9", `/p${i}`, 404, T0 + i * 2000), [], `at ${i}`);
});

test("static assets never count", () => {
  const s = new ResponseSignals({ notFound: { count: 3, windowSeconds: 60 } });
  for (const p of ["/favicon.ico", "/img/a.PNG", "/app.js.map", "/font.woff2?v=1", "/style.css"]) assert.deepEqual(s.record("203.0.113.9", p, 404, T0), []);
  assert.equal(s.state().trackedIps, 0);
});

test("401/403 floods throttle; 5xx spikes are logged app-wide only", () => {
  const s = new ResponseSignals({ authFailures: { count: 5, windowSeconds: 60 }, serverErrors: { count: 3, windowSeconds: 60 } });
  let out: any[] = [];
  for (let i = 0; i < 5; i++) out = s.record("203.0.113.9", "/api/orders/" + i, i % 2 ? 401 : 403, T0 + i);
  assert.deepEqual([out[0].type, out[0].action], ["auth_failures", "throttle"]);
  for (let i = 0; i < 3; i++) out = s.record(`198.51.100.${i}`, "/checkout", 502, T0 + i);
  assert.deepEqual([out[0].type, out[0].ip, out[0].action], ["server_errors", "", "log"]);
  assert.deepEqual(s.record("198.51.100.9", "/", 200, T0), []);
});

test("thresholds are clamped and each signal can be switched off", () => {
  const s = new ResponseSignals({ notFound: { count: 0, windowSeconds: 999999 }, authFailures: false, serverErrors: false });
  assert.equal(s.notFound!.count, 40);
  assert.equal(s.notFound!.windowSeconds, 3600);
  assert.equal(s.authFailures, null);
  for (let i = 0; i < 50; i++) assert.deepEqual(s.record("1.2.3.4", "/a", 401, T0 + i), []);
});

test("client: a 404 flood blocks the IP here and logs one incident", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_responses";
  let now = T0;
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logAllowed: false, now: () => now, burst: false });
  for (let i = 0; i < 40; i++) {
    const r = await client.check({ ip: "203.0.113.50", method: "GET", path: `/backup${i}.zip?token=secret` });
    assert.equal(r.verdict, "allowed");
    r.reportResponse!(404);
    now += 50;
  }
  const after = await client.check({ ip: "203.0.113.50", method: "GET", path: "/" });
  assert.equal(after.verdict, "blocked");
  assert.match(after.reason, /not-found responses/);
  assert.equal((await client.check({ ip: "203.0.113.51", method: "GET", path: "/" })).verdict, "allowed");
  assert.equal(client.status().responseSignals?.fired.not_found, 1);
  await client.flush();
  const logs = mock.state.logBatches.flat() as any[];
  const incident = logs.find((e) => e.rule_id === "response:not_found");
  assert.ok(incident && incident.is_incident);
  assert.equal(incident.details.response_signal.count, 40);
  assert.ok(!JSON.stringify(logs).includes("token=secret"), "query strings stay out of the log");
});

test("client: an auth-failure flood throttles; blocked requests and service traffic offer no reporter", async (t) => {
  const mock = await startMock({ rules: [{ id: "b", name: "Block admin", type: "pattern", action: "block", priority: 1, active: true, deployment_state: "enforced", criteria: { path: "^/admin" } }] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_responses2";
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logAllowed: false, burst: false, responseSignals: { authFailures: { count: 3, windowSeconds: 60 } } });
  const blocked = await client.check({ ip: "203.0.113.60", method: "GET", path: "/admin" });
  assert.equal(blocked.verdict, "blocked");
  assert.equal(blocked.reportResponse, undefined);
  for (let i = 0; i < 3; i++) (await client.check({ ip: "203.0.113.60", method: "GET", path: "/api/me" })).reportResponse!(401);
  const r = await client.check({ ip: "203.0.113.60", method: "GET", path: "/api/me" });
  assert.equal(r.verdict, "throttled");
  assert.match(r.reason, /unauthorised or forbidden/);
});

test("client: responseSignals: false turns it off", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_responses3";
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, responseSignals: false });
  const r = await client.check({ ip: "203.0.113.70", method: "GET", path: "/" });
  assert.equal(r.reportResponse, undefined);
  assert.equal(client.status().responseSignals, null);
});

test("express reports the status when the response finishes", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_responses4";
  const mw = express({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logAllowed: false, burst: false, responseSignals: { notFound: { count: 3, windowSeconds: 60 } } } as never);
  const run = () => new Promise<{ status: number }>((resolve) => {
    const listeners: (() => void)[] = [];
    const res: any = {
      statusCode: 200,
      status(c: number) { this.statusCode = c; return this; },
      send() { resolve({ status: this.statusCode }); listeners.forEach((l) => l()); return this; },
      set() { return this; },
      on(_e: string, l: () => void) { listeners.push(l); },
    };
    const req: any = { ip: "203.0.113.80", method: "GET", originalUrl: "/missing", headers: {}, socket: { remoteAddress: "203.0.113.80" } };
    mw(req, res, () => { res.status(404).send("not found"); });
  });
  for (let i = 0; i < 3; i++) assert.equal((await run()).status, 404);
  assert.equal((await run()).status, 403, "the fourth request is blocked");
});
