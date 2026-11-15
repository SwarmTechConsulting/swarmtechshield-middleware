import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import { edgeGateway, parseOrigin, originUrl, originHeaders, EDGE_HEADER } from "../src/adapters/edge.ts";
import { startMock } from "./mock-server.ts";

interface Seen { method: string; url: string; headers: IncomingMessage["headers"]; body: string }

async function startOrigin(handler: (s: Seen) => { status: number; body?: string; headers?: Record<string, string> }) {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const s = { method: req.method || "", url: req.url || "", headers: req.headers, body };
      seen.push(s);
      const r = handler(s);
      res.writeHead(r.status, r.headers || { "content-type": "text/plain" });
      res.end(r.body ?? "ok");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}`, seen, close: () => new Promise<void>((r) => server.close(() => r())) };
}

const visitor = (path: string, init: RequestInit & { ip?: string } = {}) => {
  const headers = new Headers(init.headers);
  headers.set("cf-connecting-ip", init.ip || "203.0.113.10");
  return new Request(`https://shop.example.com${path}`, { ...init, headers });
};

test("origin URLs are checked and requests map onto them", () => {
  assert.equal(typeof parseOrigin("ftp://x"), "string");
  assert.equal(typeof parseOrigin("https://u:p@x.example"), "string");
  assert.equal(typeof parseOrigin("https://x.example/?a=1"), "string");
  const o = parseOrigin("https://origin.example.com/app/") as URL;
  assert.equal(originUrl(o, "https://shop.example.com/cart?id=2"), "https://origin.example.com/app/cart?id=2");
});

test("origin headers: forwarded-for, host, secret; visitor copies and hop-by-hop dropped", () => {
  const req = new Request("https://shop.example.com/x", { headers: { "cf-connecting-ip": "203.0.113.10", [EDGE_HEADER]: "forged", connection: "keep-alive", "x-forwarded-for": "10.0.0.1" } });
  const h = originHeaders(req, { origin: "https://o.example", originSecret: "s3cret", connectionKey: "k", syncUrl: "u" }, new URL("https://o.example"));
  assert.equal(h.get(EDGE_HEADER), "s3cret");
  assert.equal(h.get("x-forwarded-for"), "10.0.0.1, 203.0.113.10");
  assert.equal(h.get("x-real-ip"), "203.0.113.10");
  assert.equal(h.get("x-forwarded-host"), "shop.example.com");
  assert.equal(h.get("x-forwarded-proto"), "https");
  assert.equal(h.get("host"), "o.example");
  assert.equal(h.get("connection"), null);
});

test("allowed requests are proxied with method, body and secret; blocked ones never reach the origin", async (t) => {
  const mock = await startMock({ rules: [{ id: "b", name: "Block admin", type: "pattern", action: "block", priority: 1, active: true, deployment_state: "enforced", criteria: { path: "^/admin" } }] });
  const origin = await startOrigin((s) => ({ status: s.url === "/missing" ? 404 : 201, body: `got ${s.method} ${s.url}`, headers: { "content-type": "text/plain", "x-app": "1" } }));
  t.after(() => Promise.all([mock.close(), origin.close()]));
  mock.state.key = "sts_conn_edge1";
  const gw = edgeGateway(() => ({ origin: origin.url, originSecret: "s3cret", connectionKey: mock.state.key, syncUrl: mock.syncUrl, logUrl: mock.logUrl, logAllowed: false }));

  const ok = await gw.fetch(visitor("/api/orders?x=1", { method: "POST", body: JSON.stringify({ a: 1 }), headers: { "content-type": "application/json", [EDGE_HEADER]: "forged" } }), {});
  assert.equal(ok.status, 201);
  assert.equal(ok.headers.get("x-app"), "1");
  assert.equal(await ok.text(), "got POST /api/orders?x=1");
  const s = origin.seen[0];
  assert.equal(s.body, '{"a":1}');
  assert.equal(s.headers[EDGE_HEADER], "s3cret", "the visitor's forged value is replaced");
  assert.equal(s.headers["x-real-ip"], "203.0.113.10");

  const blocked = await gw.fetch(visitor("/admin/users"), {});
  assert.equal(blocked.status, 403);
  assert.equal(origin.seen.length, 1, "blocked requests never reach the origin");
});

test("origin 404 floods trip response signals at the edge", async (t) => {
  const mock = await startMock({ rules: [] });
  const origin = await startOrigin(() => ({ status: 404, body: "nope" }));
  t.after(() => Promise.all([mock.close(), origin.close()]));
  mock.state.key = "sts_conn_edge2";
  const gw = edgeGateway({ origin: origin.url, connectionKey: mock.state.key, syncUrl: mock.syncUrl, logAllowed: false, burst: false, responseSignals: { notFound: { count: 3, windowSeconds: 60 } } });
  for (let i = 0; i < 3; i++) assert.equal((await gw.fetch(visitor(`/x${i}`, { ip: "198.51.100.40" }), {})).status, 404);
  assert.equal((await gw.fetch(visitor("/y", { ip: "198.51.100.40" }), {})).status, 403);
  assert.equal(origin.seen.length, 3);
});

test("an unreachable origin answers 502; a misconfigured or looping origin answers 500", async (t) => {
  const mock = await startMock({ rules: [] });
  t.after(() => mock.close());
  mock.state.key = "sts_conn_edge3";
  const base = { connectionKey: mock.state.key, syncUrl: mock.syncUrl, logAllowed: false, onError: () => {} };
  const down = edgeGateway({ ...base, origin: "http://127.0.0.1:9" });
  assert.equal((await down.fetch(visitor("/"), {})).status, 502);
  assert.equal((await edgeGateway({ ...base, origin: "not a url" }).fetch(visitor("/"), {})).status, 500);
  assert.equal((await edgeGateway({ ...base, origin: "https://shop.example.com" }).fetch(visitor("/"), {})).status, 500);
});

test("redirects from the origin go back to the visitor", async (t) => {
  const mock = await startMock({ rules: [] });
  const origin = await startOrigin(() => ({ status: 302, body: "", headers: { location: "/login" } }));
  t.after(() => Promise.all([mock.close(), origin.close()]));
  mock.state.key = "sts_conn_edge4";
  const gw = edgeGateway({ origin: origin.url, connectionKey: mock.state.key, syncUrl: mock.syncUrl, logAllowed: false });
  const r = await gw.fetch(visitor("/account"), {});
  assert.equal(r.status, 302);
  assert.equal(r.headers.get("location"), "/login");
});
