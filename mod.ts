/**
 * Honeytoken middleware for any `Request` → `Response` server: `Deno.serve`,
 * `Bun.serve`, or Node behind a fetch-style adapter. Trap paths bots scan for
 * (`/.env`, `/.git/config`, ...) get fake credentials unique to that request;
 * a fake login records when one comes back. Passive only: nothing here
 * grants access or contacts the requester.
 *
 * @module
 */

import { bait, BAIT_PATHS } from "./bait.ts";
import { memoryStore, type Store } from "./store.ts";

export type { Bait } from "./bait.ts";
export { memoryStore } from "./store.ts";
export type { Store } from "./store.ts";

/**
 * What a trap path does: serve fake secrets (`honeytoken`), serve a fake
 * login that records reused secrets (`login`), ban the ip (`ban`), or just
 * answer 404 (`404`). Every action records a {@linkcode Hit}.
 */
export type Action = "honeytoken" | "login" | "ban" | "404";

/** An action, optionally delayed by `delayMs` (capped at {@linkcode MAX_DELAY_MS}). */
export type Rule = Action | { action: Action; delayMs?: number };

/** One request to a trap path. */
export interface Hit {
  ip: string;
  ua: string | null;
  path: string;
  action: Action;
  /** Epoch milliseconds. */
  at: number;
}

/** A served secret coming back to the fake login. */
export interface Use {
  token: string;
  ip: string;
  /** Epoch milliseconds. */
  at: number;
  /** The hit that served `token`. */
  hit: Hit;
}

/** Options for {@linkcode honeypot}. Every field has a default. */
export interface Options {
  /** Trap paths and their rules. Default {@linkcode DEFAULT_PATHS}. */
  paths?: Record<string, Rule>;
  /** How long a `ban` lasts. Default 24h. */
  banMs?: number;
  /** How long hit, token and use records live. Default 90 days. */
  ttlMs?: number;
  /** Records stored per ip per day; past it, responses continue but nothing is stored. Default 20. */
  perIpDailyCap?: number;
  /** Where records go. Default {@linkcode memoryStore}. */
  store?: Store;
  /** Extra lines appended to the `/.env` bait. */
  canaries?: string[];
  /** Called on every hit. Errors are swallowed. */
  onHit?: (hit: Hit) => void | Promise<void>;
  /** Called when a served secret is posted to a `login` path. Errors are swallowed. */
  onUse?: (use: Use) => void | Promise<void>;
}

/** The bait paths as `honeytoken`, plus `/admin/login` and `/wp-login.php` as `login`. */
export const DEFAULT_PATHS: Record<string, Rule> = {
  ...Object.fromEntries(BAIT_PATHS.map((p) => [p, "honeytoken" as const])),
  "/admin/login": "login",
  "/wp-login.php": "login",
};

/** Upper bound on a rule's `delayMs`. */
export const MAX_DELAY_MS = 30_000;

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_LOGIN_VALUES = 10;
const MAX_LOGIN_VALUE_LENGTH = 64; // bait secrets are at most 40
const MAX_LOGIN_BODY = 16_384;
const MAX_IP_LENGTH = 45; // IPv6

const LOGIN_FORM = `<!doctype html>
<title>Sign in</title>
<form method="post">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button>Sign in</button>
</form>
`;

function text(
  status: number,
  body: string,
  contentType = "text/plain; charset=utf-8",
): Response {
  return new Response(body, {
    status,
    headers: { "content-type": contentType },
  });
}

async function safely<T>(
  fn: ((arg: T) => void | Promise<void>) | undefined,
  arg: T,
): Promise<void> {
  try {
    await fn?.(arg);
  } catch {
    // callbacks never change the response
  }
}

/**
 * Up to {@linkcode MAX_LOGIN_VALUES} short top-level string values from a
 * form-encoded or JSON body. Bodies without a `content-length` or over
 * {@linkcode MAX_LOGIN_BODY} bytes are not read.
 */
async function loginValues(req: Request): Promise<string[]> {
  const length = req.headers.get("content-length");
  if (!length || !(Number(length) <= MAX_LOGIN_BODY)) return [];
  try {
    const raw = await req.text();
    const parsed: unknown = req.headers.get("content-type")?.includes("json")
      ? JSON.parse(raw)
      : Object.fromEntries(new URLSearchParams(raw));
    if (typeof parsed !== "object" || parsed === null) return [];
    return Object.values(parsed)
      .filter((v): v is string =>
        typeof v === "string" && v.length <= MAX_LOGIN_VALUE_LENGTH
      )
      .slice(0, MAX_LOGIN_VALUES);
  } catch {
    return [];
  }
}

/**
 * Builds the middleware. Call the returned handler first in your server:
 * it returns a `Response` for trap paths and banned ips, or `null` to fall
 * through to the app. Pass `ip` when the runtime knows it; otherwise the
 * first `x-forwarded-for` entry is used. That fallback is only safe behind a
 * proxy that overwrites `x-forwarded-for`; otherwise pass the socket ip, or a
 * client can name any ip and get it banned.
 */
export function honeypot(
  options: Options = {},
): (req: Request, ip?: string) => Promise<Response | null> {
  const paths = options.paths ?? DEFAULT_PATHS;
  const banMs = options.banMs ?? DAY_MS;
  const ttlMs = options.ttlMs ?? 90 * DAY_MS;
  const cap = options.perIpDailyCap ?? 20;
  const store = options.store ?? memoryStore();

  return async (req, ip) => {
    ip ||= req.headers.get("x-forwarded-for")?.split(",")[0].trim()
      .slice(0, MAX_IP_LENGTH) || "unknown";
    if (await store.get("ban", ip) !== undefined) return text(403, "Forbidden");

    const path = new URL(req.url).pathname;
    const rule = Object.hasOwn(paths, path) ? paths[path] : undefined;
    if (!rule) return null;
    const { action, delayMs = 0 } = typeof rule === "string"
      ? { action: rule }
      : rule;

    // ponytail: read-then-set races under concurrency and over-admits a few
    // records; use an atomic counter in the Store if exactness matters
    const count = await store.get<number>("ip", ip) ?? 0;
    const record = count < cap;
    if (record) await store.set("ip", ip, count + 1, DAY_MS);

    const at = Date.now();
    const hit: Hit = {
      ip,
      ua: req.headers.get("user-agent"),
      path,
      action,
      at,
    };
    if (record) {
      await store.set(
        "hit",
        `${at}:${ip}:${crypto.randomUUID().slice(0, 8)}`,
        hit,
        ttlMs,
      );
    }
    await safely(options.onHit, hit);

    let res: Response;
    if (action === "honeytoken") {
      const b = bait(path, options.canaries);
      if (b && record) {
        await Promise.all(
          b.secrets.map((s) => store.set("token", s, hit, ttlMs)),
        );
      }
      res = b ? text(200, b.body, b.contentType) : text(404, "Not Found");
    } else if (action === "login") {
      if (req.method === "POST") {
        for (const token of await loginValues(req)) {
          const served = await store.get<Hit>("token", token);
          if (!served) continue;
          const use: Use = { token, ip, at, hit: served };
          if (record) {
            await store.set(
              "use",
              `${at}:${token}:${crypto.randomUUID().slice(0, 8)}`,
              use,
              ttlMs,
            );
          }
          await safely(options.onUse, use);
        }
        res = text(401, "Invalid credentials");
      } else {
        res = text(200, LOGIN_FORM, "text/html; charset=utf-8");
      }
    } else if (action === "ban") {
      await store.set("ban", ip, true, banMs);
      res = text(403, "Forbidden");
    } else {
      res = text(404, "Not Found");
    }

    if (delayMs > 0) {
      await new Promise((r) => setTimeout(r, Math.min(delayMs, MAX_DELAY_MS)));
    }
    return res;
  };
}
