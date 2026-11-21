// COPY verbatim of mail/web/worker/ipBucket.ts — keep in sync (CI checks: the ci.yml npx job diffs the two).
/** Bucket key for a caller's IP (the per-IP rate limits). Cloudflare sets cf-connecting-ip on every edge
    request and overwrites whatever the client sent, so the 'noip' fallback is unreachable today — but these
    gates used to read `if (ip && ...)`, which spells "no header, no limit": one routing mistake away from a
    real bypass. Headerless callers SHARE one bucket instead of skipping the gate (fail closed). The raw
    (nullable) ip stays for Turnstile: siteverify wants a real address or none at all, never a sentinel.

    IPv6 is bucketed by its /56 prefix, not the full address. A subscriber is routinely delegated a /56 (often
    more) and picks any address inside it per request, so a full-address key handed every request a fresh, empty
    bucket (pombus-sec on the Cloudflare OAuth start: 45 probes from 45 addresses). /56 everywhere, pre-auth
    included (pombus-sec). IPv4 stays the whole address (/32): grouping by /24 would punish everyone behind one
    CGNAT for a single abuser. An IPv4-mapped IPv6 (::ffff:a.b.c.d) is that IPv4. Anything that does not parse
    shares the 'badip' bucket (fails closed, like 'noip'): junk never mints a fresh bucket per request.

    A per-IP limit is a convenience, not the fence: a route that hits a SHARED resource needs a per-user/account
    bucket as well (see domainProbeLimited). */
export function ipBucket(ip: string | null): string {
  if (!ip) return 'noip';
  const s = ip.trim().toLowerCase().split('%')[0] ?? '';   // drop an IPv6 zone id (the URL parser refuses it)
  // Only address characters reach the URL parser: userinfo/fragments (`a:b@host#`, `x:y@[2001:db8::`) would
  // otherwise be parsed as a URL and pick an arbitrary /56 (pombus-sec).
  if (!/^[0-9a-f:.]+$/.test(s)) return 'badip';
  if (!s.includes(':')) {
    const o = s.split('.');
    // one address, one key: `01.2.3.4` and `1.2.3.4` are the same bucket
    return o.length === 4 && o.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255) ? o.map(Number).join('.') : 'badip';
  }
  let h: string;
  try {
    // The WHATWG URL parser validates the IPv6 and prints it canonical: lowercase, `::`-compressed, embedded IPv4
    // as hex — so every spelling of one address (mapped forms included) reaches the code below the same way.
    h = new URL(`http://[${s}]`).hostname.slice(1, -1);
  } catch {
    return 'badip';
  }
  const parts = h.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts[1] ? parts[1].split(':') : [];
  const g = [...head, ...Array<string>(8 - head.length - tail.length).fill('0'), ...tail].map((x) => parseInt(x, 16));
  const [a = 0, b = 0, c = 0, d = 0, , , y = 0, z = 0] = g;
  if (a === 0 && b === 0 && c === 0 && d === 0 && g[4] === 0 && g[5] === 0xffff) {   // ::ffff:a.b.c.d -> the IPv4
    return [y >> 8, y & 0xff, z >> 8, z & 0xff].join('.');
  }
  return `${[a, b, c, d & 0xff00].map((n) => n.toString(16)).join(':')}::/56`;   // 3 hextets + the top byte of the 4th
}
