/**
 * A {@linkcode Store} backed by a `Deno.Kv`-shaped store the caller opens
 * and owns. This file never calls `Deno.openKv` itself, so it stays free of
 * the `Deno` namespace.
 *
 * @module
 */

import type { Store } from "./store.ts";

/**
 * A single part of a `Deno.Kv` key. Matches `Deno.KvKeyPart`'s shape so a
 * real `Deno.Kv` satisfies {@linkcode KvLike} structurally.
 */
export type KvKeyPart =
  | Uint8Array
  | string
  | number
  | bigint
  | boolean
  | symbol;

/** The slice of `Deno.Kv` that {@linkcode kvStore} needs. */
export interface KvLike {
  /** Reads a single entry; `value` is `null` when the key is missing. */
  get(key: readonly KvKeyPart[]): Promise<{ value: unknown }>;
  /** Writes an entry, expiring after `options.expireIn` milliseconds. */
  set(
    key: readonly KvKeyPart[],
    value: unknown,
    options?: { expireIn?: number },
  ): Promise<unknown>;
  /** Iterates entries whose key starts with `selector.prefix`. */
  list(
    selector: { prefix: readonly KvKeyPart[] },
  ): AsyncIterable<{ key: readonly KvKeyPart[]; value: unknown }>;
}

/** Builds the KV key for a kind/key pair, namespaced under "honeypot". */
function kvKey(kind: string, key: string): readonly KvKeyPart[] {
  return ["honeypot", kind, key];
}

/** A {@linkcode Store} backed by a caller-supplied `Deno.Kv`-like store. */
export function kvStore(kv: KvLike): Store {
  return {
    async get<T>(kind: string, key: string): Promise<T | undefined> {
      const entry = await kv.get(kvKey(kind, key));
      return entry.value === null ? undefined : entry.value as T;
    },

    async set(
      kind: string,
      key: string,
      value: unknown,
      ttlMs: number,
    ): Promise<void> {
      await kv.set(kvKey(kind, key), value, { expireIn: ttlMs });
    },

    async list<T>(kind: string): Promise<{ key: string; value: T }[]> {
      const result: { key: string; value: T }[] = [];
      for await (const entry of kv.list({ prefix: ["honeypot", kind] })) {
        const key = entry.key[entry.key.length - 1];
        result.push({ key: key as string, value: entry.value as T });
      }
      return result;
    },
  };
}
