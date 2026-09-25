/**
 * Honeytoken middleware for `Deno.serve`. Trap paths bots scan for (`/.env`,
 * `/.git/config`, ...) get fake credentials unique to that request; a fake
 * login records when one comes back.
 *
 * @module
 */

/** Returns a response for trap paths, or `null` to fall through to the app. */
export function honeypot(_req: Request): Response | null {
  return null;
}
