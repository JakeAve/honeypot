import { assert, assertEquals } from "@std/assert";
import {
  type Hit,
  honeypot,
  MAX_DELAY_MS,
  memoryStore,
  type Use,
} from "./mod.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const get = (path: string, init?: RequestInit) =>
  new Request(`http://x${path}`, init);
const post = (path: string, body: string, headers?: Record<string, string>) =>
  get(path, {
    method: "POST",
    body,
    headers: { "content-length": String(body.length), ...headers },
  });

Deno.test("unconfigured path returns null", async () => {
  const hp = honeypot();
  assertEquals(await hp(get("/"), "1.1.1.1"), null);
  assertEquals(await hp(get("/constructor"), "1.1.1.1"), null);
});

Deno.test("honeytoken response contains a secret stored under token", async () => {
  const store = memoryStore();
  const hits: Hit[] = [];
  const hp = honeypot({ store, onHit: (h) => void hits.push(h) });
  const res = await hp(get("/.env"), "1.1.1.1");
  assert(res);
  assertEquals(res.status, 200);
  const body = await res.text();
  const tokens = await store.list<Hit>("token");
  assert(tokens.length > 0);
  for (const { key, value } of tokens) {
    assert(body.includes(key));
    assertEquals(value.path, "/.env");
  }
  assertEquals(hits.length, 1);
  assertEquals((await store.list("hit")).length, 1);
});

Deno.test("posting a served secret to /admin/login records a use and calls onUse", async () => {
  const store = memoryStore();
  const uses: Use[] = [];
  const hp = honeypot({ store, onUse: (u) => void uses.push(u) });
  await hp(get("/.git/config"), "1.1.1.1");
  const [{ key: token }] = await store.list("token");

  const form = await hp(get("/admin/login"), "2.2.2.2");
  assertEquals(form?.status, 200);
  assert((await form!.text()).includes('name="password"'));

  const res = await hp(
    post(
      "/admin/login",
      new URLSearchParams({ username: "deploy", password: token }).toString(),
    ),
    "2.2.2.2",
  );
  assertEquals(res?.status, 401);
  assertEquals(uses.length, 1);
  assertEquals(uses[0].token, token);
  assertEquals(uses[0].ip, "2.2.2.2");
  assertEquals(uses[0].hit.ip, "1.1.1.1");
  assertEquals((await store.list("use")).length, 1);

  await hp(
    post("/admin/login", JSON.stringify({ user: "x", pass: token }), {
      "content-type": "application/json",
    }),
    "2.2.2.2",
  );
  assertEquals(uses.length, 2);
});

Deno.test("login always returns 401 even when onUse throws", async () => {
  const store = memoryStore();
  const hp = honeypot({
    store,
    onHit: () => Promise.reject(new Error("boom")),
    onUse: () => {
      throw new Error("boom");
    },
  });
  await hp(get("/.env"), "1.1.1.1");
  const [{ key: token }] = await store.list("token");
  const res = await hp(
    post("/admin/login", new URLSearchParams({ password: token }).toString()),
    "1.1.1.1",
  );
  assertEquals(res?.status, 401);
  assertEquals(await res!.text(), "Invalid credentials");
});

Deno.test("oversized login body is ignored", async () => {
  const store = memoryStore();
  const uses: Use[] = [];
  const hp = honeypot({ store, onUse: (u) => void uses.push(u) });
  await hp(get("/.env"), "1.1.1.1");
  const [{ key: token }] = await store.list("token");
  const res = await hp(
    post("/admin/login", new URLSearchParams({ password: token }).toString(), {
      "content-length": "100000",
    }),
    "1.1.1.1",
  );
  assertEquals(res?.status, 401);
  assertEquals((await store.list("use")).length, 0);
  assertEquals(uses.length, 0);
});

Deno.test("ban path returns 403 and any later request from that ip returns 403 until banMs elapses", async () => {
  const hp = honeypot({ paths: { "/trap": "ban" }, banMs: 30 });
  assertEquals((await hp(get("/trap"), "3.3.3.3"))?.status, 403);
  assertEquals((await hp(get("/"), "3.3.3.3"))?.status, 403);
  assertEquals(await hp(get("/"), "4.4.4.4"), null);
  await sleep(40);
  assertEquals(await hp(get("/"), "3.3.3.3"), null);
});

Deno.test("404 rule returns 404 and stores a hit", async () => {
  const store = memoryStore();
  const hp = honeypot({ store, paths: { "/x": "404", "/y": "honeytoken" } });
  assertEquals((await hp(get("/x"), "1.1.1.1"))?.status, 404);
  assertEquals((await hp(get("/y"), "1.1.1.1"))?.status, 404);
  const hits = await store.list<Hit>("hit");
  assertEquals(hits.map((h) => h.value.action).sort(), ["404", "honeytoken"]);
});

Deno.test("concurrent hits from one ip are both stored", async () => {
  const store = memoryStore();
  const hp = honeypot({ store, paths: { "/x": "404" } });
  await Promise.all([hp(get("/x"), "1.1.1.1"), hp(get("/x"), "1.1.1.1")]);
  assertEquals((await store.list("hit")).length, 2);
});

Deno.test("delayMs delays the response by at least that long", async () => {
  const hp = honeypot({ paths: { "/slow": { action: "404", delayMs: 50 } } });
  const start = performance.now();
  await hp(get("/slow"), "1.1.1.1");
  assert(performance.now() - start >= 49);
});

Deno.test("delayMs is capped at MAX_DELAY_MS", async () => {
  const realSetTimeout = globalThis.setTimeout;
  let requested: number | undefined;
  globalThis.setTimeout = ((fn: () => void, ms?: number) => {
    requested = ms;
    fn();
    return 0;
  }) as unknown as typeof setTimeout;
  try {
    const hp = honeypot({
      paths: { "/slow": { action: "404", delayMs: 999_999 } },
    });
    await hp(get("/slow"), "1.1.1.1");
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
  assertEquals(requested, MAX_DELAY_MS);
});

Deno.test("cap stops storing after perIpDailyCap hits but still responds", async () => {
  const store = memoryStore();
  const hp = honeypot({
    store,
    perIpDailyCap: 2,
    paths: { "/x": "404", "/b": "ban" },
  });
  for (let i = 0; i < 5; i++) {
    assertEquals((await hp(get("/x"), "1.1.1.1"))?.status, 404);
  }
  assertEquals((await store.list("hit")).length, 2);
  assertEquals((await hp(get("/b"), "1.1.1.1"))?.status, 403);
  assertEquals(await store.get("ban", "1.1.1.1"), true);
});

Deno.test("x-forwarded-for is used when ip is omitted", async () => {
  const store = memoryStore();
  const hp = honeypot({ store });
  await hp(
    get("/.env", { headers: { "x-forwarded-for": " 5.5.5.5 , 10.0.0.1" } }),
  );
  const [{ value }] = await store.list<Hit>("hit");
  assertEquals(value.ip, "5.5.5.5");
  await hp(get("/config.json"));
  const ips = (await store.list<Hit>("hit")).map((h) => h.value.ip);
  assert(ips.includes("unknown"));
});
