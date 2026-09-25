import { assert, assertEquals } from "@std/assert";
import { bait, BAIT_PATHS } from "./bait.ts";

Deno.test("each bait path returns a body containing all its secrets", () => {
  for (const path of BAIT_PATHS) {
    const result = bait(path);
    assert(result, `expected bait for ${path}`);
    assert(result.secrets.length > 0, `expected secrets for ${path}`);
    for (const secret of result.secrets) {
      assert(
        result.body.includes(secret),
        `expected body for ${path} to contain secret ${secret}`,
      );
    }
  }
});

Deno.test("two calls never share a secret", () => {
  for (const path of BAIT_PATHS) {
    const a = bait(path)!;
    const b = bait(path)!;
    for (const secret of a.secrets) {
      assert(!b.secrets.includes(secret), `secret reused for ${path}`);
    }
  }
});

Deno.test("canaries appear only in /.env", () => {
  const canaries = ["CANARY_TOKEN=abc123"];

  const env = bait("/.env", canaries)!;
  assert(env.body.includes("CANARY_TOKEN=abc123"));

  for (const path of BAIT_PATHS) {
    if (path === "/.env") continue;
    const result = bait(path, canaries)!;
    assert(!result.body.includes("CANARY_TOKEN=abc123"));
  }
});

Deno.test("unknown path returns null", () => {
  assertEquals(bait("/nope"), null);
});
