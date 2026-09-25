# @jakeave/honeypot

Honeytoken middleware for any `Request` → `Response` server: Deno, Bun or Node.
A honeytoken is a fake secret planted where only an intruder would look. Paths
bots scan for (`/.env`, `/.git/config`, `/config.json`, `/.aws/credentials`) get
believable fake credentials, unique per request; a fake login (`/admin/login`,
`/wp-login.php`) records when one comes back. Passive only: nothing it serves
grants access, it never contacts or probes the requester, and every fake host
ends in `.internal`.

## Install

```bash
deno add jsr:@jakeave/honeypot        # Deno
bunx jsr add @jakeave/honeypot        # Bun
npx jsr add @jakeave/honeypot         # Node
```

## Wire it

`honeypot(options?)` returns `(req, ip?) => Promise<Response | null>`. Call it
first: a `Response` means it handled the request, `null` means fall through to
your app. Pass the client ip when the runtime gives you one; without it the
first `x-forwarded-for` entry is used.

Deno:

```ts
import { honeypot } from "@jakeave/honeypot";

const trap = honeypot();
Deno.serve(async (req, info) =>
  await trap(req, info.remoteAddr.hostname) ?? app(req)
);
```

Bun:

```ts
import { honeypot } from "@jakeave/honeypot";

const trap = honeypot();
Bun.serve({
  async fetch(req, server) {
    return await trap(req, server.requestIP(req)?.address) ?? app(req);
  },
});
```

Node: `node:http` hands you an `IncomingMessage`, not a `Request`. Converting
both ways is yours to supply (`@hono/node-server` or a few lines of your own);
the ip is on the socket.

```ts
import { createServer } from "node:http";
import { honeypot } from "@jakeave/honeypot";

const trap = honeypot();
createServer(async (req, res) => {
  const hit = await trap(toRequest(req), req.socket.remoteAddress);
  if (hit) return writeResponse(res, hit); // your adapter
  app(req, res);
}).listen(3000);
```

## Paths

Default: the bait paths as `honeytoken`, the logins as `login`; `paths` replaces
them. Each rule is an action, or an action with a `delayMs` (capped at 30
seconds) to slow scanners down:

```ts
const trap = honeypot({
  paths: {
    "/.env": "honeytoken", // fake secrets, recorded as tokens
    "/admin/login": { action: "login", delayMs: 2_000 }, // records reused tokens
    "/wp-admin/setup-config.php": "ban", // 403 this ip for banMs (default 24h)
    "/phpmyadmin/": { action: "404", delayMs: 5_000 }, // record and 404
  },
});
```

Every action records a hit. Other options: `banMs`, `ttlMs`, `perIpDailyCap`
(records per ip per day, default 20), `canaries` (extra `/.env` lines), `store`,
`onHit`, `onUse`.

## Deno Deploy: KV

The default store is in memory and lost on restart. On Deno Deploy use KV:

```ts
import { honeypot } from "@jakeave/honeypot";
import { kvStore } from "@jakeave/honeypot/kv";

const store = kvStore(await Deno.openKv());
const trap = honeypot({ store });
```

## Reading results

```ts
import type { Use } from "@jakeave/honeypot";

for (const { value } of await store.list<Use>("use")) {
  console.log(value.ip, "used a token served to", value.hit.ip, value.hit.path);
}
```

Kinds: `hit`, `token`, `use`, `ban`. For alerts, `onUse` fires the moment a
served secret comes back; post it to your own webhook (callback errors are
swallowed and never change the response):

```ts
const trap = honeypot({
  store,
  onUse: (use) =>
    void fetch(Deno.env.get("ALERT_WEBHOOK")!, {
      method: "POST",
      body: JSON.stringify(use),
    }),
});
```

## Store

Anything implementing this works, so file, Mongo or SQL adapters are a few lines
each. Every `set` carries a TTL; expired records must not come back.

```ts
interface Store {
  get<T>(kind: string, key: string): Promise<T | undefined>;
  set(kind: string, key: string, value: unknown, ttlMs: number): Promise<void>;
  list<T>(kind: string): Promise<{ key: string; value: T }[]>;
}
```

## Retention

Hits, tokens and uses expire after 90 days by default (`ttlMs`), bans after
`banMs`. IPs are personal data; nothing is kept forever.

## Develop

```bash
deno task setup          # once per clone: wire .githooks
deno task check          # fmt, lint, typecheck
deno task test
deno task test:runtimes  # smoke test under node and bun (skips missing ones)
```
