# SwarmTech Shield edge gateway (Cloudflare Workers)

A ready-to-deploy Worker that puts SwarmTech Shield in front of any site, whatever it is built with. Every request is screened at Cloudflare's edge with cached rules. Only allowed requests are forwarded to your origin, so your app needs no code changes.

Screening never calls SwarmTech Shield per request: the Worker syncs rules in the background and uploads logs in batches. A flood is stopped at the edge and costs your Shield workspace almost nothing.

## Deploy

1. Copy this folder, then run `npm install`.
2. In `wrangler.toml`:
   - set `ORIGIN_URL` to where your app really lives (for example `https://origin.example.com`, or the platform URL such as `https://myapp.onrender.com`);
   - set `SHIELD_SYNC_URL` and `SHIELD_LOG_URL` from the console;
   - uncomment `routes` with your hostname.
3. Add the secrets:
   ```sh
   npx wrangler secret put SHIELD_CONNECTION_KEY    # the app's connection key from the console
   npx wrangler secret put SHIELD_ORIGIN_SECRET     # e.g. the output of: openssl rand -hex 32
   ```
4. Deploy with `npm run deploy`.

## Lock the origin

The gateway only protects traffic that goes through it, so make the origin refuse anything else. Every forwarded request carries `x-shield-edge: <SHIELD_ORIGIN_SECRET>`. A visitor can't set it, because the gateway removes any copy sent from outside.

Express:

```js
app.use((req, res, next) => {
  if (req.get("x-shield-edge") !== process.env.SHIELD_ORIGIN_SECRET) return res.status(403).send("Forbidden");
  next();
});
```

Anything else: reject requests whose `x-shield-edge` header doesn't equal the secret. Compare in constant time where your language offers it. Better still, also allow only Cloudflare's IP ranges at the origin's firewall, or use a Cloudflare Tunnel so the origin has no public address at all.

The visitor's IP reaches the origin as `X-Real-IP`, and is appended to `X-Forwarded-For` (use the right-most entry).

## What it does

- **Screening:** the full middleware runs, with rules, the blocklist, threat lists, deep inspection, decoys, outcome protection, virtual patches and under-attack mode. The client IP is `CF-Connecting-IP`, which Cloudflare sets.
- **Response signals:** the origin's answers count. 404 floods block the IP, 401/403 floods throttle it, and 5xx spikes raise an alert.
- **Errors:** if the origin can't be reached the gateway answers 502, or 504 after 30 s (`originTimeoutMs`).
- **Redirects** from the origin go back to the visitor. They are never followed.
- **Streaming:** WebSocket upgrades and streaming responses pass straight through.

The gateway answers blocked, throttled and shed requests itself, so they never reach your app.

## Limits

- The rules live in memory per Worker isolate. A fresh isolate does one sync before it screens, waiting at most 1.5 s and then applying the fail mode. Busy sites keep isolates warm.
- Local blocks (burst, response signals) apply per isolate. Blocks that matter go to the blocklist through SwarmTech Shield and reach every isolate within the next sync (30 s).
- Request bodies are read for inspection up to 64 KB (`maxBodyBytes`) from a copy, and the original is forwarded untouched.
