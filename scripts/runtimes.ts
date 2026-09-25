// Runs scripts/smoke.ts under each runtime on PATH; skips missing ones.
let failed = false;
for (const runtime of ["node", "bun"]) {
  try {
    const { success } = await new Deno.Command(runtime, {
      args: ["scripts/smoke.ts"],
      stdout: "inherit",
      stderr: "inherit",
    }).output();
    if (success) console.log(`${runtime} ok`);
    else {
      console.error(`${runtime} failed`);
      failed = true;
    }
  } catch (e) {
    if (!(e instanceof Deno.errors.NotFound)) throw e;
    console.log(`skip ${runtime}`);
  }
}
if (failed) Deno.exit(1);
