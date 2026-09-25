/**
 * The storage contract every adapter (memory, KV, ...) implements, plus the
 * default in-memory implementation.
 *
 * @module
 */

/** Backing storage for honeypot records, keyed by kind and key. */
export interface Store {
  /** Returns the stored value, or `undefined` if missing or expired. */
  get<T>(kind: string, key: string): Promise<T | undefined>;
  /** Stores a value under `kind`/`key`, expiring after `ttlMs`. */
  set(kind: string, key: string, value: unknown, ttlMs: number): Promise<void>;
  /** Returns all live (non-expired) entries for a kind. */
  list<T>(kind: string): Promise<{ key: string; value: T }[]>;
}

interface Entry {
  value: unknown;
  expiresAt: number;
}

/** Above this many entries in a kind, `set` sweeps out expired ones. */
const SWEEP_THRESHOLD = 10_000;

/** An in-memory {@linkcode Store}. Records are lost on process restart. */
export function memoryStore(): Store {
  const kinds = new Map<string, Map<string, Entry>>();

  return {
    // deno-lint-ignore require-await
    async get<T>(kind: string, key: string): Promise<T | undefined> {
      const entry = kinds.get(kind)?.get(key);
      if (!entry) return undefined;
      if (entry.expiresAt <= Date.now()) {
        kinds.get(kind)?.delete(key);
        return undefined;
      }
      return entry.value as T;
    },

    // deno-lint-ignore require-await
    async set(
      kind: string,
      key: string,
      value: unknown,
      ttlMs: number,
    ): Promise<void> {
      let entries = kinds.get(kind);
      if (!entries) {
        entries = new Map();
        kinds.set(kind, entries);
      }
      if (entries.size > SWEEP_THRESHOLD) {
        // ponytail: full sweep past 10k entries per kind; switch to a
        // min-heap of expiries if a kind grows large
        const now = Date.now();
        for (const [k, e] of entries) {
          if (e.expiresAt <= now) entries.delete(k);
        }
      }
      entries.set(key, { value, expiresAt: Date.now() + ttlMs });
    },

    // deno-lint-ignore require-await
    async list<T>(kind: string): Promise<{ key: string; value: T }[]> {
      const entries = kinds.get(kind);
      if (!entries) return [];
      const now = Date.now();
      const result: { key: string; value: T }[] = [];
      for (const [key, entry] of entries) {
        if (entry.expiresAt <= now) {
          entries.delete(key);
        } else {
          result.push({ key, value: entry.value as T });
        }
      }
      return result;
    },
  };
}
