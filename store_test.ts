import { assertEquals } from "@std/assert";
import { memoryStore } from "./store.ts";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

Deno.test("set then get returns the value", async () => {
  const store = memoryStore();
  await store.set("ip", "1.2.3.4", { hits: 1 }, 60_000);
  assertEquals(await store.get("ip", "1.2.3.4"), { hits: 1 });
});

Deno.test("expired entry reads as undefined", async () => {
  const store = memoryStore();
  await store.set("ip", "1.2.3.4", { hits: 1 }, 1);
  await sleep(5);
  assertEquals(await store.get("ip", "1.2.3.4"), undefined);
});

Deno.test("list omits expired entries and includes live ones", async () => {
  const store = memoryStore();
  await store.set("ip", "live", "a", 60_000);
  await store.set("ip", "dead", "b", 1);
  await sleep(5);
  assertEquals(await store.list("ip"), [{ key: "live", value: "a" }]);
});

Deno.test("kinds are isolated", async () => {
  const store = memoryStore();
  await store.set("ip", "shared-key", "ip-value", 60_000);
  await store.set("path", "shared-key", "path-value", 60_000);
  assertEquals(await store.get("ip", "shared-key"), "ip-value");
  assertEquals(await store.get("path", "shared-key"), "path-value");
  assertEquals(await store.list("ip"), [{
    key: "shared-key",
    value: "ip-value",
  }]);
});
