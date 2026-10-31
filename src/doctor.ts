// `pombus doctor` — a cheap, read-only health check. Validates the key against GET /v0/auth/me
// (via ScopeBinding.resolve) and tells the human, in i18n, whether the key works and at what scope, or
// what is wrong (no key / invalid key / core unreachable). One request, no writes.

import { CoreClient, CoreError, type FetchLike } from "./client.js";
import { ScopeBinding } from "./scope.js";
import { humanCodeForBoot, humanMessage, resolveLocale, type Locale } from "./i18n.js";

export interface DoctorOptions {
  apiKey?: string | undefined;
  locale?: Locale;
  fetchImpl?: FetchLike | undefined;
  baseUrl?: string | undefined;
  out?: (line: string) => void;
}

export interface DoctorResult {
  ok: boolean;
  /** The resolved scope when ok, else null. */
  scope: string | null;
  /** The i18n code emitted (doctor_ok on success, else a boot/error code). */
  code: string;
}

export async function runDoctor(opts: DoctorOptions): Promise<DoctorResult> {
  const locale: Locale = opts.locale ?? resolveLocale();
  const out = opts.out ?? ((l: string) => process.stderr.write(l + "\n"));

  const key = (opts.apiKey ?? "").trim();
  if (!key) {
    out(humanMessage("no_api_key", locale));
    return { ok: false, scope: null, code: "no_api_key" };
  }

  const client = new CoreClient({
    apiKey: key,
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });

  try {
    const scope = await ScopeBinding.resolve(client);
    // doctor_ok's message ends with "Scope: " — append the resolved scope type (a stable, non-secret
    // identifier: inbox/domain/pod/organization). Not localized: it is an API constant, not prose.
    out(humanMessage("doctor_ok", locale) + scope.scopeType);
    return { ok: true, scope: scope.scopeType, code: "doctor_ok" };
  } catch (e) {
    // Same bridge the server boot uses: a rejected key (not_found) => auth_failed, unreachable core =>
    // network, anything else => unknown. Never leaks the key or a URL (CoreError carries only a code).
    const code = e instanceof CoreError ? humanCodeForBoot(e.code) : "unknown";
    out(humanMessage(code, locale));
    return { ok: false, scope: null, code };
  }
}
