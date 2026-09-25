# honeypot

JSR package `@jakeave/honeypot`: honeytoken middleware for web-standard
`Request`/`Response` servers (Deno, Bun, Node). Used by Jake's apps on Deno
Deploy. Deno 2 + TypeScript.

## Rules

- No runtime dependencies. `@std/assert` is test-only.
- Cross-runtime: no `Deno`, `Bun` or Node globals in published source. Erasable
  TS only (no enums, no parameter properties, imports with extensions). The
  caller passes the client IP. `kv.ts` types Deno.Kv structurally.
- Passive only: never grant access, never contact or probe the requester, no zip
  bombs. Per-path delays are allowed, capped at 30s. Fake hosts must be ones
  nobody owns (`*.internal`).
- Storage goes through the three-method `Store` interface (`get`, `set`, `list`,
  all with TTL). Adapters are one file each; never call a backend directly from
  the handler.
- Stored hits expire (default 90 days); IPs are personal data.
- Tests colocated as `*_test.ts`.

## Layout

- `mod.ts`: handler, options, defaults.
- `store.ts`: `Store` interface and in-memory store.
- `bait.ts`: fake file templates and secret generation.
- `kv.ts`: Deno KV `Store` adapter, exported as `./kv`.
- `scripts/smoke.ts`: run under node and bun by `deno task test:runtimes`.

## Commands

```bash
deno task setup          # once per clone: core.hooksPath -> .githooks
deno task check          # fmt, lint, typecheck (pre-commit and pre-push)
deno task test           # (pre-commit and pre-push)
deno task test:runtimes  # smoke test under node and bun (pre-push)
deno publish             # pre-push runs it with --dry-run
```

Specs live in `docs/specs/`, plans in `docs/plans/` (both git-ignored).
