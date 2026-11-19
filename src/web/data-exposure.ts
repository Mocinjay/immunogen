/**
 * Live backend exposure check for URL mode — the question every vibe-coded
 * Supabase / Firebase app has to answer: can a stranger read my data with
 * the public key my site ships?
 *
 * From the page and its same-origin scripts it extracts the Supabase
 * project URL + anon / publishable key, the Firebase `databaseURL` /
 * `projectId`, and the table / collection names the client code queries
 * (`.from("orders")`, `collection(db, "users")`). Then, using only that
 * public key, it asks:
 *
 *   WEB-DATA-01 — Supabase: `HEAD /rest/v1/<table>` with
 *   `Prefer: count=exact`. The response's `Content-Range` carries the row
 *   count and no row data. A count above zero means anyone can read the
 *   table: CRITICAL. (Zero rows can mean "empty" or "RLS hides every row" —
 *   not reported.) Tables named by the project's public OpenAPI root
 *   (`GET /rest/v1/`), when the anon key may read it, are checked too.
 *
 *   WEB-DATA-02 — Firebase Realtime Database: `GET <databaseURL>/.json?shallow=true`
 *   returns only top-level key names. Any non-null answer means the
 *   database is world-readable: CRITICAL.
 *
 *   WEB-DATA-03 — Firestore: list one document of each collection with a
 *   field mask that returns document names only. A document coming back
 *   means the collection is world-readable: CRITICAL.
 *
 * Read-only by construction: HEAD and GET only, no row values are read or
 * stored, nothing is written. Requests go only to Supabase / Firebase hosts
 * (`*.supabase.co`, `*.firebaseio.com`, `*.firebasedatabase.app`,
 * `firestore.googleapis.com`) named in the site's own bundle, through the
 * same SSRF guard and pinned connections as every other URL-mode request,
 * with a per-request timeout and fixed caps. Consent is the `--authorize`
 * flag the whole URL mode already requires; `--no-data-probes` turns this
 * check off.
 */
import type { FetchDeps, FetchedTarget } from "./fetch-target.js";

import type { Finding } from "../core/types.js";
import { USER_AGENT } from "../version.js";

/** Most Supabase tables / Firestore collections checked per scan. */
const MAX_TABLES = 25;
const MAX_COLLECTIONS = 10;

/** Supabase project URL. Group 1: project ref. */
const SUPABASE_URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.co/g;

/** A JWT (Supabase legacy anon key shape). */
const JWT_RE = /eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}/g;

/** Supabase's newer public key format. */
const PUBLISHABLE_KEY_RE = /sb_publishable_[\w-]{16,}/g;

/** Firebase Realtime Database URL. */
const FIREBASE_DB_URL_RE = /https:\/\/[a-z0-9-]+(?:\.firebaseio\.com|\.[a-z0-9-]+\.firebasedatabase\.app)/g;

/** Firebase `projectId` in a web config object. */
const FIREBASE_PROJECT_ID_RE = /projectId\s*:\s*["']([a-z0-9-]{4,40})["']/;

/** `.from("table")` — supabase-js table access. */
const SUPABASE_FROM_RE = /\.from\(\s*["'`]([A-Za-z_]\w{0,62})["'`]\s*\)/g;

/** `collection(db, "name")` / `.collection("name")` — Firestore access. */
// eslint-disable-next-line security/detect-unsafe-regex -- optional group is one class run then a literal comma; benchmarked linear on 100k-char adversarial input
const FIRESTORE_COLLECTION_RE = /collection\(\s*(?:[\w$.]+\s*,\s*)?["'`]([A-Za-z_][\w-]{0,62})["'`]\s*[,)]/g;

/** What the bundle reveals about the app's backend. */
export interface BackendConfig {
  supabase?: { url: string; key: string };
  firebaseDatabaseUrl?: string;
  firestoreProjectId?: string;
  tables: string[];
  collections: string[];
}

/** Decoded JWT payload, or undefined. */
function jwtPayload(token: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** Unique capture-group-1 values of `re` across `texts`, in first-seen order, capped. */
function captures(texts: readonly string[], re: RegExp, cap: number): string[] {
  const seen = new Set<string>();
  for (const text of texts) {
    for (const match of text.matchAll(re)) {
      const value = match[1];
      if (value !== undefined) {
        seen.add(value);
      }
      if (seen.size >= cap) {
        return [...seen];
      }
    }
  }
  return [...seen];
}

/** Reads the backend configuration the page and its scripts expose. */
export function extractBackendConfig(target: FetchedTarget): BackendConfig {
  const texts = [target.body, ...target.scripts.map((script) => script.body)];
  const config: BackendConfig = {
    tables: captures(texts, SUPABASE_FROM_RE, MAX_TABLES),
    collections: captures(texts, FIRESTORE_COLLECTION_RE, MAX_COLLECTIONS),
  };

  const ref = captures(texts, SUPABASE_URL_RE, 1).at(0);
  if (ref !== undefined) {
    // The anon JWT names its project (`ref`) and role; never use a key for another project or role.
    const anonJwt = texts
      .flatMap((text) => [...text.matchAll(JWT_RE)].map((match) => match[0]))
      .find((token) => {
        const payload = jwtPayload(token);
        return payload?.["role"] === "anon" && (payload["ref"] === undefined || payload["ref"] === ref);
      });
    const publishable = texts.flatMap((text) => [...text.matchAll(PUBLISHABLE_KEY_RE)].map((match) => match[0])).at(0);
    const key = anonJwt ?? publishable;
    if (key !== undefined) {
      config.supabase = { url: `https://${ref}.supabase.co`, key };
    }
  }

  const databaseUrl = texts.flatMap((text) => [...text.matchAll(FIREBASE_DB_URL_RE)].map((match) => match[0])).at(0);
  if (databaseUrl !== undefined) {
    config.firebaseDatabaseUrl = databaseUrl;
  }
  for (const text of texts) {
    const projectId = text.match(FIREBASE_PROJECT_ID_RE)?.[1];
    if (projectId !== undefined) {
      config.firestoreProjectId = projectId;
      break;
    }
  }
  return config;
}

/** True when the config gives the probe anything to check. */
export function hasBackend(config: BackendConfig): boolean {
  return (
    config.supabase !== undefined ||
    config.firebaseDatabaseUrl !== undefined ||
    (config.firestoreProjectId !== undefined && config.collections.length > 0)
  );
}

/** A guarded, time-limited request. */
async function request(url: string, init: RequestInit, deps: FetchDeps, timeoutMs: number): Promise<Response> {
  const parsed = new URL(url);
  await deps.assertAllowed?.(parsed);
  return deps.fetch(parsed.toString(), {
    ...init,
    headers: { "user-agent": USER_AGENT, ...(init.headers as Record<string, string> | undefined) },
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
  });
}

/** Row count from a PostgREST `Content-Range` header (`0-0/42`, `*\/42`), or undefined. */
export function rowCount(contentRange: string | null): number | undefined {
  const total = contentRange?.split("/").at(1);
  if (total === undefined || total === "*") {
    return undefined;
  }
  const count = Number.parseInt(total, 10);
  return Number.isFinite(count) ? count : undefined;
}

/** Table names the project's OpenAPI root lists, when the anon key may read it. */
async function openApiTables(supabase: { url: string; key: string }, deps: FetchDeps, timeoutMs: number): Promise<string[]> {
  try {
    const response = await request(`${supabase.url}/rest/v1/`, { headers: { apikey: supabase.key, authorization: `Bearer ${supabase.key}` } }, deps, timeoutMs);
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      return [];
    }
    const spec = (await response.json()) as { paths?: Record<string, unknown> };
    return Object.keys(spec.paths ?? {})
      .map((path) => path.replace(/^\//, ""))
      .filter((name) => /^[A-Za-z_]\w{0,62}$/.test(name))
      .slice(0, MAX_TABLES);
  } catch {
    return [];
  }
}

/** Outcome of the exposure probes. */
export interface DataExposureResult {
  findings: Finding[];
  /** Human-readable probe targets that could not be checked. */
  failed: string[];
}

/** Builds one WEB-DATA finding. */
function exposureFinding(ruleId: string, url: string, message: string, remediation: string, matchedText: string): Finding {
  return {
    ruleId,
    category: "web",
    detectorName: "data-exposure",
    file: url,
    line: 1,
    severity: "CRITICAL",
    confidence: "HIGH",
    message,
    remediation,
    matchedText,
  };
}

/** Runs every applicable exposure probe for `config` (see the module comment). Never throws. */
export async function probeDataExposure(config: BackendConfig, deps: FetchDeps, timeoutMs: number): Promise<DataExposureResult> {
  const findings: Finding[] = [];
  const failed: string[] = [];

  if (config.supabase !== undefined) {
    const { url, key } = config.supabase;
    const tables = [...new Set([...config.tables, ...(await openApiTables(config.supabase, deps, timeoutMs))])].slice(0, MAX_TABLES);
    for (const table of tables) {
      try {
        const response = await request(
          `${url}/rest/v1/${encodeURIComponent(table)}?select=*`,
          { method: "HEAD", headers: { apikey: key, authorization: `Bearer ${key}`, prefer: "count=exact", range: "0-0" } },
          deps,
          timeoutMs,
        );
        const count = rowCount(response.headers.get("content-range"));
        if ((response.status === 200 || response.status === 206) && count !== undefined && count > 0) {
          findings.push(
            exposureFinding(
              "WEB-DATA-01",
              url,
              `Supabase table "${table}" is readable by anyone: the anon key your site ships returned ${String(count)} row(s). Row Level Security is off or a policy lets everyone read it.`,
              `Enable RLS on public.${table} ("alter table public.${table} enable row level security;") and add policies that only return a user's own rows, e.g. using (auth.uid() = user_id). Then re-run this check.`,
              table,
            ),
          );
        }
      } catch {
        failed.push(`supabase:${table}`);
      }
    }
  }

  if (config.firebaseDatabaseUrl !== undefined) {
    const databaseUrl = config.firebaseDatabaseUrl;
    try {
      const response = await request(`${databaseUrl}/.json?shallow=true`, { method: "GET" }, deps, timeoutMs);
      const text = response.ok ? (await response.text()).trim() : "";
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
      }
      if (response.ok && text !== "" && text !== "null") {
        findings.push(
          exposureFinding(
            "WEB-DATA-02",
            databaseUrl,
            "Firebase Realtime Database is readable by anyone: an unauthenticated request listed its top-level keys.",
            'Replace the database rules with ones that require sign-in and scope reads to the user, e.g. ".read": "auth != null && auth.uid === $uid" under a per-user path, and deploy them.',
            databaseUrl,
          ),
        );
      }
    } catch {
      failed.push("firebase-rtdb");
    }
  }

  if (config.firestoreProjectId !== undefined) {
    const projectId = config.firestoreProjectId;
    for (const collection of config.collections) {
      const base = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents/${encodeURIComponent(collection)}`;
      try {
        const response = await request(`${base}?pageSize=1&mask.fieldPaths=__immunogen_none__`, { method: "GET" }, deps, timeoutMs);
        const body = response.ok ? ((await response.json()) as { documents?: unknown[] }) : undefined;
        if (!response.ok) {
          await response.body?.cancel().catch(() => undefined);
        }
        if (Array.isArray(body?.documents) && body.documents.length > 0) {
          findings.push(
            exposureFinding(
              "WEB-DATA-03",
              `https://firestore.googleapis.com/v1/projects/${projectId}`,
              `Firestore collection "${collection}" is readable by anyone: an unauthenticated request listed its documents.`,
              `Tighten firestore.rules so ${collection} documents are only readable by their owner (e.g. allow read: if request.auth != null && request.auth.uid == resource.data.userId) and deploy the rules.`,
              collection,
            ),
          );
        }
      } catch {
        failed.push(`firestore:${collection}`);
      }
    }
  }

  return { findings, failed };
}
