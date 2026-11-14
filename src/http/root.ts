// R2d — the friendly root page. A HUMAN who opens the MCP endpoint in a browser (GET, Accept text/html,
// no Bearer) lands here instead of a bare 401; a real MCP client never does (it POSTs with Accept
// application/json / text/event-stream and a Bearer, so it falls through to the normal fail-closed MCP
// path — the worker, not this module, makes that distinction). Self-contained HTML: no script, no
// external font, no external image (same CSP-friendliness as the consent screen), tokens ported from it.
//
// Everything visible comes from the i18n dictionary (oauth-i18n.ts ROOT_TEXT) in the three mandated
// locales. There are no attacker-controlled values on this page (no query reflection), but the one
// dynamic value (the localized strings) is still run through esc() as a belt-and-braces XSS fence.

import { type Locale, ROOT_TEXT } from "./oauth-i18n.js";

/** HTML-escape for text / double-quoted attribute contexts (same five chars as consent.ts esc). */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Localized root-page string. Looked up in ROOT_TEXT (not the consent dict); throws on an unknown id
 *  (every id is a literal here) so a missing string can never ship silently — mirrors consent's t(). */
function t(id: string, locale: Locale): string {
  const entry = ROOT_TEXT[id];
  if (!entry) throw new Error(`root i18n: unknown id ${id}`);
  return entry[locale];
}

/** The Pombus horizontal lockup, identical to the consent screen's (currentColor, no external asset). */
const BRAND_SVG = `<svg role="img" aria-label="Pombus" xmlns="http://www.w3.org/2000/svg" fill-rule="evenodd" clip-rule="evenodd" viewBox="0 0 198284 43410"><g><g><g><path fill="currentColor" d="M17584 0l4226 0c9499,0 17302,7635 17579,17072l5 0 0 512 0 18023 -19697 7803 -19697 -7803 0 -18023 0 -512 10 0c272,-9437 8079,-17072 17574,-17072zm-2625 33078l3839 4217c239,263 545,397 899,397 354,0 660,-134 899,-397l3843 -4217c43,-43 77,-95 115,-143l956 0c746,0 1382,-416 1688,-1095 296,-683 177,-1434 -325,-1984l-5814 -6377c-363,-397 -827,-603 -1362,-603 -536,0 -999,206 -1358,603l-5818 6377c-502,550 -622,1301 -320,1984 301,679 936,1095 1682,1095l961 0c34,48 67,100 115,143l0 0zm-6268 -23975l7831 7620c371,360 581,855 581,1372 0,517 -210,1012 -580,1372l-7832 7621c-357,347 -835,541 -1333,541 -1057,0 -1914,-856 -1914,-1913 0,-517 209,-1012 580,-1372l6425 -6249 -6425 -6248c-371,-360 -580,-856 -580,-1372 0,-1057 857,-1914 1914,-1914 498,0 976,195 1333,542zm22212 0l-7831 7620c-371,360 -580,855 -580,1372 0,517 209,1012 580,1372l7831 7621c357,347 836,541 1334,541 1056,0 1913,-856 1913,-1913 0,-517 -209,-1012 -579,-1372l-6426 -6249 6426 -6248c370,-360 579,-856 579,-1372 0,-1057 -857,-1914 -1913,-1914 -498,0 -977,195 -1334,542l0 0zm-28465 8992c0,1405 1139,2544 2544,2544 1404,0 2543,-1139 2543,-2544 0,-1404 -1139,-2543 -2543,-2543 -1405,0 -2544,1139 -2544,2543l0 0zm29631 0c0,1405 1139,2544 2544,2544 1404,0 2543,-1139 2543,-2544 0,-1404 -1139,-2543 -2543,-2543 -1405,0 -2544,1139 -2544,2543z"/><path fill="currentColor" fill-rule="nonzero" d="M68230 39187l0 -18262 3284 0 80 3043 -347 -160c356,-1050 939,-1847 1749,-2389 810,-543 1758,-815 2844,-815 1353,0 2478,338 3377,1015 899,676 1571,1575 2016,2696 445,1122 668,2368 668,3738 0,1371 -227,2617 -681,3738 -454,1122 -1131,2021 -2029,2697 -899,677 -2025,1015 -3378,1015 -712,0 -1375,-125 -1989,-374 -614,-249 -1139,-605 -1575,-1068 -436,-463 -743,-1006 -922,-1629l321 -267 0 7022 -3418 0zm6782 -6461c1033,0 1847,-414 2443,-1242 596,-827 895,-1971 895,-3431 0,-1459 -299,-2603 -895,-3430 -596,-828 -1410,-1242 -2443,-1242 -694,0 -1290,174 -1789,521 -498,347 -885,867 -1161,1562 -276,694 -414,1557 -414,2589 0,1033 133,1896 400,2590 267,695 654,1215 1162,1562 507,347 1108,521 1802,521z"/></g></g></g></svg>`;

/** Render the root page in the given locale. Pure string → the worker sets the 200 + content-type. */
export function renderRoot(locale: Locale): string {
  const L = locale;
  const title = esc(t("root_title", L));
  const heading = esc(t("root_heading", L));
  const body = esc(t("root_body", L));
  const site = esc(t("root_site", L));
  return `<!doctype html>
<html lang="${esc(L)}">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title}</title>
<style>
  :root {
    color-scheme: light dark;
    --card: #ffffff; --surface: #f4f5f6; --border: #e4e6e9; --ink: #0b0e11; --muted: #5c636b; --dim: #878e96;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --card: #0b0e11; --surface: #171c22; --border: #262d35; --ink: #e6e9ec; --muted: #8a9099; --dim: #8a9099;
    }
  }
  * { box-sizing: border-box; }
  body {
    font: 14px/1.6 system-ui, -apple-system, sans-serif; color: var(--ink); background: var(--surface);
    min-height: 100vh; min-height: 100dvh; margin: 0; padding: 44px 20px;
    display: flex; align-items: center; justify-content: center;
  }
  .card {
    width: 100%; max-width: 440px; background: var(--card); border: 1px solid var(--border);
    border-radius: 20px; padding: 32px 30px; text-align: center;
    box-shadow: 0 24px 60px -24px rgba(0, 0, 0, 0.35);
  }
  .brand { display: flex; justify-content: center; margin-bottom: 18px; color: var(--ink); }
  .brand svg { height: 28px; width: auto; display: block; }
  h1 { font-size: 18px; font-weight: 600; letter-spacing: -0.01em; margin: 0 0 8px; color: var(--ink); }
  p { font-size: 13.5px; color: var(--muted); margin: 0 0 14px; }
  .site { font-size: 12.5px; color: var(--dim); margin: 0; }
</style>
</head>
<body>
  <main class="card">
    <span class="brand">${BRAND_SVG}</span>
    <h1>${heading}</h1>
    <p>${body}</p>
    <p class="site">${site}</p>
  </main>
</body>
</html>`;
}
