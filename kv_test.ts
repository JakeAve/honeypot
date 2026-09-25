import { assertEquals } from "@std/assert";
import { kvStore } from "./kv.ts";

Deno.test("set then get round-trips through KV", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    const store = kvStore(kv);
    await store.set("ip", "1.2.3.4", { hits: 1 }, 60_000);
    assertEquals(await store.get("ip", "1.2.3.4"), { hits: 1 });
  } finally {
    kv.close();
  }
});

Deno.test("list returns entries under the kind prefix only", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    const store = kvStore(kv);
    await store.set("ip", "shared-key", "ip-value", 60_000);
    await store.set("path", "shared-key", "path-value", 60_000);
    assertEquals(await store.list("ip"), [{
      key: "shared-key",
      value: "ip-value",
    }]);
  } finally {
    kv.close();
  }
});

Deno.test("missing key reads as undefined", async () => {
  const kv = await Deno.openKv(":memory:");
  try {
    const store = kvStore(kv);
    assertEquals(await store.get("ip", "missing"), undefined);
  } finally {
    kv.close();
  }
});
