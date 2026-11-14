import { test } from "node:test";
import assert from "node:assert/strict";
import { SwarmTechShield } from "../src/index.ts";
import { resolveFetchIp } from "../src/adapters/fetch.ts";
import { isPrivateIp, NO_TRUSTED_SOURCE, BEHIND_PROXY } from "../src/ip.ts";
import { startMock } from "./mock-server.ts";

const blockSpoofed = [{ id: "r1", name: "Block", type: "ip_block", action: "block", priority: 1, deployment_state: "enforced", criteria: { ips: ["203.0.113.9"] } }];
const req = (headers: Record<string, string>) => new Request("https://app.test/x", { headers });
const vercel = { ipHeaders: ["x-real-ip"], ipPolicy: { kind: "platform" as const, platform: "vercel" } };
const requireConfig = { ipHeaders: [], ipPolicy: { kind: "require-config" as const } };
const base44 = { ipHeaders: [], ipPolicy: { kind: "assume-xff" as const, platform: "base44" } };

test("off a detected platform, a client-set header is never believed", () => {
  const r = resolveFetchIp(req({ "x-real-ip": "203.0.113.9", "x-forwarded-for": "203.0.113.9" }), {} as never, requireConfig);
  assert.equal(r.ip, "");
  assert.deepEqual(r.source, { method: "none", trust: "none", warning: NO_TRUSTED_SOURCE });
});

test("platform, configured and assumed sources are labelled as such", () => {
  assert.deepEqual(resolveFetchIp(req({ "x-real-ip": "198.51.100.4" }), {} as never, vercel), { ip: "198.51.100.4", source: { method: "vercel:x-real-ip", trust: "platform" } });
  const h = { "x-my-ip": "198.51.100.5", "x-forwarded-for": "6.6.6.6, 198.51.100.6, 10.0.0.2" };
  assert.deepEqual(resolveFetchIp(req(h), { trustedHeader: "X-My-IP" } as never, requireConfig).source, { method: "header:x-my-ip", trust: "configured" });
  assert.equal(resolveFetchIp(req(h), { trustedHeader: "X-My-IP" } as never, requireConfig).ip, "198.51.100.5");
  const two = resolveFetchIp(req(h), { trustedProxyCount: 2 } as never, requireConfig);
  assert.deepEqual(two, { ip: "198.51.100.6", source: { method: "x-forwarded-for:2", trust: "configured" } });
  assert.deepEqual(resolveFetchIp(req(h), { getClientIp: () => "198.51.100.7" } as never, requireConfig), { ip: "198.51.100.7", source: { method: "getClientIp", trust: "configured" } });
  assert.deepEqual(resolveFetchIp(req(h), {} as never, base44).source, { method: "base44:x-forwarded-for:1", trust: "assumed" });
});

test("Next.js off Vercel: a spoofed x-real-ip can't get a victim blocked, and the setup is reported", async (t) => {
  delete process.env.VERCEL;
  delete process.env.VERCEL_ENV;
  const mock = await startMock({ rules: blockSpoofed });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_ipsource_next";
  const errors: string[] = [];
  const mw = SwarmTechShield.nextjs({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, onError: (e) => errors.push(e.message) });
  const res = await mw(req({ "x-real-ip": "203.0.113.9", "x-vercel-ip-country": "KP" }));
  assert.equal(res, undefined, "the header is ignored, so the rule doesn't fire on a spoofed IP");
  assert.ok(errors.some((m) => m === NO_TRUSTED_SOURCE));
  assert.deepEqual(mock.state.syncCalls[0].ip_source, { method: "none", trust: "none", warning: NO_TRUSTED_SOURCE });
});

test("Next.js with trustedHeader enforces IP rules off Vercel", async (t) => {
  delete process.env.VERCEL;
  const mock = await startMock({ rules: blockSpoofed });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_ipsource_next_cfg";
  const mw = SwarmTechShield.nextjs({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, trustedHeader: "x-client-ip" });
  assert.equal((await mw(req({ "x-client-ip": "203.0.113.9" })))?.status, 403);
  assert.deepEqual(mock.state.syncCalls[0].ip_source, { method: "header:x-client-ip", trust: "configured" });
});

test("generic screenRequest needs an explicit source", async (t) => {
  const mock = await startMock({ rules: blockSpoofed });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_ipsource_generic";
  const opts = { connectionKey: mock.state.key, syncUrl: mock.syncUrl, onError: () => {} };
  assert.equal((await SwarmTechShield.screenRequest(req({ "x-forwarded-for": "203.0.113.9" }), opts)).verdict, "allowed");
  const withIp = await SwarmTechShield.screenRequest(req({}), { ...opts, getClientIp: () => "203.0.113.9" });
  assert.equal(withIp.verdict, "blocked");
});

test("Express: socket address is trusted; a private peer with X-Forwarded-For warns about a proxy", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_ipsource_express";
  const errors: string[] = [];
  const mw = SwarmTechShield.express({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, onError: (e) => errors.push(e.message) });
  const run = (ip: string, headers: Record<string, string>) =>
    new Promise<void>((resolve) => {
      const r = { ip, method: "GET", originalUrl: "/", headers, socket: { remoteAddress: ip } };
      const res = { statusCode: 200, status() { return this; }, set() { return this; }, send() { resolve(); return this; } };
      mw(r as never, res as never, () => resolve());
    });
  await run("198.51.100.20", {});
  assert.equal(errors.length, 0);
  assert.deepEqual(mock.state.syncCalls.at(-1)!.ip_source, { method: "socket", trust: "socket" });
  await run("10.0.0.5", { "x-forwarded-for": "198.51.100.21" });
  assert.ok(errors.includes(BEHIND_PROXY));
});

test("private ranges", () => {
  for (const ip of ["10.1.2.3", "172.20.0.1", "192.168.1.1", "127.0.0.1", "::1", "fd00::1", "100.64.0.1"]) assert.ok(isPrivateIp(ip), ip);
  for (const ip of ["198.51.100.1", "8.8.8.8", "2001:db8::1", ""]) assert.ok(!isPrivateIp(ip), ip);
});
