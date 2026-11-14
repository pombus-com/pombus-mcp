// OAuth i18n — the locale machinery + the root-page copy, in the three mandated locales (AGENTS.md §2):
// en-US, pt-BR, es-419. Keyed by a stable, locale-free id; nothing visible is hardcoded.
//
// R3 note: the consent screen moved to the WEBMAIL (the Worker delegates the human decision), so the
// consent dictionary that used to live here is gone. What remains is used by the Worker itself: the
// locale negotiation (pickLocale / parseAcceptLanguage) and the friendly root page (ROOT_TEXT), both
// consumed by root.ts and worker.ts.

export type Locale = "en-US" | "pt-BR" | "es-419";

export const OAUTH_LOCALES: readonly Locale[] = ["en-US", "pt-BR", "es-419"];

/** Match a single raw tag ("pt", "pt-BR", "es-419", "en-GB"...) to one of the three supported locales
 *  by language prefix (region only matters for Spanish, which is always es-419). Returns null when it
 *  matches none — so a garbage ?hl= simply doesn't resolve and the caller falls through to the next
 *  source (the lixo is NEVER reflected). This is the one place the prefix rule lives. */
function matchLocale(raw: string | null): Locale | null {
  const v = (raw ?? "").trim().toLowerCase();
  if (v.startsWith("pt")) return "pt-BR";
  if (v.startsWith("es")) return "es-419";
  if (v.startsWith("en")) return "en-US";
  return null;
}

/** Pick the screen locale by precedence: scan the sources in order and take the FIRST that resolves to
 *  a supported locale; en-US is the last resort. The caller passes, in order of strength:
 *    [ ?hl= , Accept-Language , ?locale= ]
 *  — the human's explicit click, then their browser default, then the agent's hint. A source that
 *  matches nothing is skipped, so a garbage value never wins and never surfaces. */
export function pickLocale(sources: (string | null)[]): Locale {
  for (const s of sources) {
    const m = matchLocale(s);
    if (m) return m;
  }
  return "en-US";
}

/** Extract the highest-priority language tag from an Accept-Language header — just the first tag,
 *  before the first comma or ';q='. ponytail: we don't parse the full q-value list; the browser lists
 *  its preferred language first, and if that first tag matches none of our three, pickLocale falls
 *  through to the next source anyway. Returns null for an empty/absent header. */
export function parseAcceptLanguage(header: string | null): string | null {
  const first = (header ?? "").split(",")[0]?.split(";")[0]?.trim();
  return first ? first : null;
}

type Dict = Record<Locale, string>;

/** The friendly root page (R2d) — the page a HUMAN sees if they open the MCP endpoint in a browser
 *  (a real MCP client never hits it: it GETs with Accept text/html and no Bearer). Three locales like
 *  everything else; keyed by a stable id. Content-free of any secret — it only names the product and
 *  how to use the endpoint. */
export const ROOT_TEXT: Record<string, Dict> = {
  root_title: {
    "en-US": "Pombus — MCP endpoint",
    "pt-BR": "Pombus — endpoint MCP",
    "es-419": "Pombus — endpoint MCP",
  },
  root_heading: {
    "en-US": "This is the Pombus MCP endpoint",
    "pt-BR": "Este é o endpoint MCP do Pombus",
    "es-419": "Este es el endpoint MCP de Pombus",
  },
  root_body: {
    "en-US": "Add this URL to your AI client (Claude and others) as a remote MCP connector. It is an API surface, not a website.",
    "pt-BR": "Adicione esta URL ao seu cliente de IA (Claude e outros) como conector MCP remoto. É uma superfície de API, não um site.",
    "es-419": "Agrega esta URL a tu cliente de IA (Claude y otros) como conector MCP remoto. Es una superficie de API, no un sitio web.",
  },
  root_site: {
    "en-US": "Learn more at pombus.com",
    "pt-BR": "Saiba mais em pombus.com",
    "es-419": "Más información en pombus.com",
  },
};
