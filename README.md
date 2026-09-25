# @jakeave/honeypot

Honeytoken middleware for `Deno.serve`. Requests for paths bots scan for
(`/.env`, `/.git/config`, `/wp-login.php`, ...) get believable fake credentials,
unique per request. A fake login records when one of them comes back, linking
the scanner to whoever used what it harvested.

Passive only: nothing it serves grants access, and it never contacts the
requester.

## Develop

```bash
deno task setup   # once per clone: wire .githooks
deno task check   # fmt, lint, typecheck
deno task test
```
