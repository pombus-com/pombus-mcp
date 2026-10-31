// i18n — human-facing error messages in the three mandated locales (AGENTS.md §2): en-US, pt-BR,
// es-419. Never hardcode a user-visible string; it comes from this dictionary keyed by a stable,
// locale-free error code. Tool errors returned TO THE MODEL are protocol text and stay en-US fixed;
// only messages a human reads (e.g. the server refusing to start, printed to stderr) are localized.
//
// Locale selection: POMBUS_LOCALE wins, then LANG/LC_ALL, else en-US. We match on the language (and
// region for the Spanish variant) prefix, so "pt_BR.UTF-8" -> pt-BR and "es_MX" -> es-419.

export type Locale = "en-US" | "pt-BR" | "es-419";

const LOCALES: readonly Locale[] = ["en-US", "pt-BR", "es-419"];

/** Every stable error code the server can surface to a human maps to one entry per locale. A code
 *  with no entry falls back to `unknown` — present in all three so no path is ever string-less. */
type Dict = Record<Locale, string>;

// Every entry here MUST be reachable by a real human path. Two human paths exist:
//   (1) the server boot failure a person sees on stderr when `pombus mcp` fails to come up, and
//   (2) the `pombus init` / `pombus doctor` installer, which talks to a human at the terminal.
// Codes that only ever reach the MODEL (inside a tool call) are NOT human i18n — they stay en-US
// protocol text in server.ts (`error: <code>`), never in this dict.
// Boot-reachable codes (path 1):
//   - no_api_key: the key env var is unset (server.ts, before any request).
//   - auth_failed: /v0/auth/me rejected the key at boot (invalid/expired).
//   - network:    the core was unreachable at boot.
//   - unknown:    the last-resort fallback for a boot error with no mapped code (bin.ts catch).
// Installer-reachable codes (path 2): see INSTALLER_CODES below.
const MESSAGES: Record<string, Dict> = {
  no_api_key: {
    "en-US": "POMBUS_API_KEY is not set. Export your Pombus API key and try again.",
    "pt-BR": "POMBUS_API_KEY não está definida. Exporte sua chave de API do Pombus e tente de novo.",
    "es-419": "POMBUS_API_KEY no está definida. Exporta tu clave de API de Pombus e inténtalo de nuevo.",
  },
  auth_failed: {
    "en-US": "Could not authenticate with Pombus. Check that POMBUS_API_KEY is valid.",
    "pt-BR": "Não foi possível autenticar no Pombus. Verifique se POMBUS_API_KEY é válida.",
    "es-419": "No se pudo autenticar en Pombus. Verifica que POMBUS_API_KEY sea válida.",
  },
  network: {
    "en-US": "Could not reach the Pombus API. Check your connection and try again.",
    "pt-BR": "Não foi possível acessar a API do Pombus. Verifique sua conexão e tente de novo.",
    "es-419": "No se pudo conectar con la API de Pombus. Revisa tu conexión e inténtalo de nuevo.",
  },
  unknown: {
    "en-US": "Something went wrong talking to Pombus.",
    "pt-BR": "Algo deu errado na comunicação com o Pombus.",
    "es-419": "Algo salió mal al comunicarse con Pombus.",
  },

  // ---- installer: `pombus init` / `pombus doctor` human lines (path 2) ----
  // init progress / results
  init_prompt_key: {
    "en-US": "Paste your Pombus API key (input hidden): ",
    "pt-BR": "Cole sua chave de API do Pombus (entrada oculta): ",
    "es-419": "Pega tu clave de API de Pombus (entrada oculta): ",
  },
  init_inbox_created: {
    "en-US": "Created inbox: ",
    "pt-BR": "Caixa criada: ",
    "es-419": "Casilla creada: ",
  },
  init_config_written: {
    "en-US": "MCP config written for ",
    "pt-BR": "Config MCP gravada para ",
    "es-419": "Configuración MCP guardada para ",
  },
  init_key_power: {
    "en-US":
      "Heads up: your agent can do everything this key can — read, send and delete mail, and manage keys and webhooks. The key is stored in plain text in that config file; revoke it in Pombus › Keys if it leaks.",
    "pt-BR":
      "Atenção: seu agente pode fazer tudo que esta chave permite — ler, enviar e apagar e-mails, e gerenciar chaves e webhooks. A chave fica em texto puro nesse arquivo de config; revogue em Pombus › Chaves se ela vazar.",
    "es-419":
      "Atención: tu agente puede hacer todo lo que esta clave permite — leer, enviar y borrar correos, y administrar claves y webhooks. La clave queda en texto plano en ese archivo de configuración; revócala en Pombus › Claves si se filtra.",
  },
  init_restart_client: {
    "en-US": "Restart your client to load the Pombus MCP server.",
    "pt-BR": "Reinicie seu cliente para carregar o servidor MCP do Pombus.",
    "es-419": "Reinicia tu cliente para cargar el servidor MCP de Pombus.",
  },
  init_done: {
    "en-US": "Done. One command and it's running.",
    "pt-BR": "Pronto. Um comando e tá rodando.",
    "es-419": "Listo. Un comando y está funcionando.",
  },
  // detection / print fallback
  init_no_client: {
    "en-US":
      "No supported client config was found to write safely. Printing the MCP block below — paste it into your client's config yourself.",
    "pt-BR":
      "Nenhuma config de cliente compatível foi encontrada para gravar com segurança. Imprimindo o bloco MCP abaixo — cole na config do seu cliente.",
    "es-419":
      "No se encontró una configuración de cliente compatible para escribir con seguridad. Imprimiendo el bloque MCP abajo — pégalo en la configuración de tu cliente.",
  },
  init_print_only_client: {
    "en-US":
      "This client's config format is not written automatically (to avoid corrupting it). Paste the block below into its config file.",
    "pt-BR":
      "O formato de config deste cliente não é gravado automaticamente (para não corrompê-lo). Cole o bloco abaixo no arquivo de config dele.",
    "es-419":
      "El formato de configuración de este cliente no se escribe automáticamente (para no dañarlo). Pega el bloque de abajo en su archivo de configuración.",
  },
  // doctor report lines
  doctor_ok: {
    "en-US": "Your Pombus API key is valid. Scope: ",
    "pt-BR": "Sua chave de API do Pombus é válida. Escopo: ",
    "es-419": "Tu clave de API de Pombus es válida. Alcance: ",
  },
};

// The installer human codes — the single source the anti-orphan guard unions with the boot-reachable
// set. A code here with no caller in init.ts/doctor.ts is still dictionary theater; a code used by the
// installer with no entry here is a missing string. Keeping the list explicit makes the guard
// mechanical without reparsing TypeScript.
const INSTALLER_CODES: readonly string[] = [
  "init_prompt_key",
  "init_inbox_created",
  "init_config_written",
  "init_key_power",
  "init_restart_client",
  "init_done",
  "init_no_client",
  "init_print_only_client",
  "doctor_ok",
];

/** The installer-reachable human codes (path 2). Exposed so the anti-orphan contract test can union
 *  them with the boot-reachable set and prove the dictionary has no orphan and no missing string. */
export function installerCodes(): readonly string[] {
  return INSTALLER_CODES;
}

/** Map a boot-time CoreError code to the human i18n code a person should see. A boot failure is one
 *  of exactly two things to a human: the key was rejected (any 401/403/404 at /v0/auth/me collapses to
 *  `not_found`, which at startup means "bad key" -> auth_failed) or the core was unreachable
 *  (`network`). Anything else is `unknown`. This is the bridge that makes auth_failed/network
 *  reachable — without it they were dictionary theater. */
export function humanCodeForBoot(coreErrorCode: string): string {
  if (coreErrorCode === "network") return "network";
  if (coreErrorCode === "not_found") return "auth_failed";
  return "unknown";
}

/** Resolve the active locale from the environment. */
export function resolveLocale(env: NodeJS.ProcessEnv = process.env): Locale {
  const raw = (env["POMBUS_LOCALE"] ?? env["LC_ALL"] ?? env["LANG"] ?? "").toLowerCase();
  if (raw.startsWith("pt")) return "pt-BR";
  if (raw.startsWith("es")) return "es-419";
  return "en-US";
}

/** The human message for a stable error code, in the active locale. Unknown codes fall back to the
 *  `unknown` entry — never a missing string. */
export function humanMessage(code: string, locale: Locale = resolveLocale()): string {
  const entry = MESSAGES[code] ?? MESSAGES["unknown"]!;
  return entry[locale];
}

/** Exposed for the contract test: the dictionary must cover all three locales for every code. */
export function allLocales(): readonly Locale[] {
  return LOCALES;
}

export function messageCodes(): readonly string[] {
  return Object.keys(MESSAGES);
}

export function messagesForTest(): Record<string, Dict> {
  return MESSAGES;
}
