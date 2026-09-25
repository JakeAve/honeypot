// Runs unchanged under node, bun and deno: exercises the handler end to end.
import { strictEqual } from "node:assert/strict";
import { honeypot } from "../mod.ts";
import type { Use } from "../mod.ts";

const uses: Use[] = [];
const hp = honeypot({ onUse: (u) => void uses.push(u) });
const ip = "203.0.113.7";

strictEqual(await hp(new Request("http://x/"), ip), null);

const env = await hp(new Request("http://x/.env"), ip);
strictEqual(env?.status, 200);
const body = await env.text();
const token = body.match(/^API_KEY=(.+)$/m)?.[1];
strictEqual(typeof token, "string");

const login = await hp(
  new Request("http://x/admin/login", {
    method: "POST",
    body: new URLSearchParams({ username: "admin", password: token! }),
  }),
  ip,
);
strictEqual(login?.status, 401);
strictEqual(uses.length, 1);
strictEqual(uses[0].token, token);

console.log("smoke ok");
