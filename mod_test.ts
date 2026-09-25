import { assertEquals } from "@std/assert";
import { honeypot } from "./mod.ts";

Deno.test("non-trap path falls through", () => {
  assertEquals(honeypot(new Request("http://x/")), null);
});
