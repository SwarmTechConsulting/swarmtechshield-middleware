import { test } from "node:test";
import assert from "node:assert/strict";
import { createClient } from "../src/client.ts";
import { OutcomeTracker, DEFAULT_DISTRIBUTED } from "../src/defence.ts";
import { startMock } from "./mock-server.ts";

const T0 = Date.parse("2026-11-14T20:00:00Z");

/** A proxy pool: every attempt from a new IP, for a new account, all failing. */
function stuff(tracker: OutcomeTracker, n: number) {
  for (let i = 0; i < n; i++) tracker.report({ type: "login", ip: `203.0.${Math.floor(i / 250)}.${i % 250}`, user: `victim${i}@mail.test`, success: false });
}

test("a proxy pool slips past per-IP and per-account limits but trips the app-wide detector", () => {
  let now = T0;
  const t = new OutcomeTracker(undefined, () => now);
  stuff(t, 40);
  assert.equal(t.check("/login", "203.0.0.1", "victim1@mail.test"), null, "no single IP or account crossed a limit");
  const d = t.loginDefence("/login", "198.51.100.77");
  assert.ok(d, "defence on");
  assert.equal(d!.response, "challenge");
  assert.equal(d!.throttle, false);
  assert.equal(d!.episode!.failures, 40);
  assert.equal(d!.episode!.ips, 40);
  assert.ok(!t.loginDefence("/login", "198.51.100.78")!.episode, "the episode is reported once");
  assert.equal(t.loginDefence("/home", "198.51.100.78"), null, "only on login paths");
  now += (DEFAULT_DISTRIBUTED.windowSeconds + DEFAULT_DISTRIBUTED.cooldownSeconds + 5) * 1000;
  assert.equal(t.loginDefence("/login", "198.51.100.78"), null, "ends after the cooldown");
});

test("ordinary traffic doesn't trip it: mostly successes, or one account under brute force", () => {
  const now = T0;
  const busy = new OutcomeTracker(undefined, () => now);
  for (let i = 0; i < 200; i++) busy.report({ type: "login", ip: `198.51.100.${i % 200}`, user: `u${i}`, success: i % 3 !== 0 });
  assert.equal(busy.loginDefence("/login", "1.1.1.1"), null, "a third failing is normal");
  const brute = new OutcomeTracker(undefined, () => now);
  for (let i = 0; i < 60; i++) brute.report({ type: "login", ip: `203.0.113.${i}`, user: "ceo@corp.test", success: false });
  assert.equal(brute.loginDefence("/login", "1.1.1.1"), null, "one account: the per-account limit's job");
  assert.ok(brute.check("/login", "1.1.1.1", "ceo@corp.test"), "which does fire");
});

test("throttle-unknown lets returning users' IPs through", () => {
  const now = T0;
  const t = new OutcomeTracker({ login: { distributed: { response: "throttle-unknown" } } }, () => now);
  t.report({ type: "login", ip: "198.51.100.10", user: "alice", success: true });
  stuff(t, 40);
  assert.equal(t.loginDefence("/login", "198.51.100.10")!.throttle, false);
  assert.equal(t.loginDefence("/login", "203.0.113.200")!.throttle, true);
});

test("switched off with distributed: false", () => {
  const t = new OutcomeTracker({ login: { distributed: false } }, () => T0);
  stuff(t, 100);
  assert.equal(t.loginDefence("/login", "1.1.1.1"), null);
});

test("client: challenge flag, one reported episode without usernames, status", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_stuffing";
  const client = createClient({ connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logAllowed: false });
  for (let i = 0; i < 40; i++) client.reportOutcome({ type: "login", ip: `203.0.113.${i}`, user: `victim${i}@mail.test`, success: false });
  const first = await client.check({ ip: "198.51.100.5", method: "POST", path: "/login" });
  assert.equal(first.verdict, "allowed");
  assert.ok(first.challenge?.reason.includes("Credential stuffing"));
  assert.equal(first.stuffingEpisode?.failures, 40);
  const second = await client.check({ ip: "198.51.100.6", method: "POST", path: "/login" });
  assert.ok(second.challenge && !second.stuffingEpisode);
  assert.equal(client.status().loginDefence?.active, true);
  await client.flush();
  const logs = mock.state.logBatches.flat() as any[];
  assert.equal(logs.length, 1, "allowed traffic isn't logged, but the episode is");
  assert.equal(logs[0].is_incident, true);
  assert.equal(logs[0].details.stuffing_episode.users, 40);
  assert.ok(!JSON.stringify(logs).includes("victim"), "usernames never leave the app");
});
