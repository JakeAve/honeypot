/**
 * Fake file bodies for trap paths. Pure: no I/O, no `Deno`/`Bun`/Node
 * globals — only the Web Crypto `crypto` global, available on every
 * runtime this package targets.
 *
 * @module
 */

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

const TEXT_PLAIN = "text/plain; charset=utf-8";
const APPLICATION_JSON = "application/json";

function randomString(length: number, charset: string): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += charset[b % charset.length];
  return out;
}

function awsAccessKeyId(): string {
  return "AKIA" + randomString(16, UPPER_ALNUM);
}

function awsSecretAccessKey(): string {
  return randomString(40, ALNUM);
}

function password(): string {
  return randomString(24, ALNUM);
}

/** A fake file: its bytes, the `Content-Type` to serve it with, and every secret embedded in `body`. */
export interface Bait {
  body: string;
  contentType: string;
  secrets: string[];
}

function envBait(canaries: readonly string[]): Bait {
  const dbPassword = password();
  const sessionSecret = password();
  const apiKey = password();
  const lines = [
    "NODE_ENV=production",
    "PORT=3000",
    `DATABASE_URL=postgres://app:${dbPassword}@db.internal:5432/app`,
    `SESSION_SECRET=${sessionSecret}`,
    `API_KEY=${apiKey}`,
    ...canaries,
  ];
  return {
    body: lines.join("\n") + "\n",
    contentType: TEXT_PLAIN,
    secrets: [dbPassword, sessionSecret, apiKey],
  };
}

function gitConfigBait(): Bait {
  const deployPassword = password();
  const body = `[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://deploy:${deployPassword}@git.internal/app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
`;
  return { body, contentType: TEXT_PLAIN, secrets: [deployPassword] };
}

function configJsonBait(): Bait {
  const dbPassword = password();
  const jwtSecret = password();
  const body = JSON.stringify(
    {
      env: "production",
      database: { host: "db.internal", user: "app", password: dbPassword },
      auth: { jwtSecret },
    },
    null,
    2,
  ) + "\n";
  return {
    body,
    contentType: APPLICATION_JSON,
    secrets: [dbPassword, jwtSecret],
  };
}

function awsCredentialsBait(): Bait {
  const accessKeyId = awsAccessKeyId();
  const secretAccessKey = awsSecretAccessKey();
  const body = `[default]
aws_access_key_id = ${accessKeyId}
aws_secret_access_key = ${secretAccessKey}
region = us-east-1
`;
  return {
    body,
    contentType: TEXT_PLAIN,
    secrets: [accessKeyId, secretAccessKey],
  };
}

/** Trap paths `bait` has a template for. */
export const BAIT_PATHS: readonly string[] = [
  "/.env",
  "/.git/config",
  "/config.json",
  "/.aws/credentials",
];

/**
 * Builds a fake file for a trap path with fresh random secrets.
 *
 * `canaries` are appended verbatim as extra lines, `/.env` only — pass
 * caller-supplied tokens to trace where a leaked file resurfaces.
 * Returns `null` when `path` isn't one of `BAIT_PATHS`.
 */
export function bait(path: string, canaries?: string[]): Bait | null {
  switch (path) {
    case "/.env":
      return envBait(canaries ?? []);
    case "/.git/config":
      return gitConfigBait();
    case "/config.json":
      return configJsonBait();
    case "/.aws/credentials":
      return awsCredentialsBait();
    default:
      return null;
  }
}
