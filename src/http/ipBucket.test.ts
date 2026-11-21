// The SAME vectors as mail/web/worker/ipBucket.test.ts (this file's ipBucket.ts is a copy of the webmail's).
import { test } from "node:test";
import assert from "node:assert/strict";
import { ipBucket } from "./ipBucket.js";

test("ipBucket: every address of one /56 shares ONE bucket, whatever the spelling", () => {
  const same = ["2001:db8:a:b00::1", "2001:db8:a:bff::2", "2001:DB8:A:BAB:ffff:ffff:ffff:ffff", "2001:0db8:000a:0b01:1:2:3:4",
    "2001:db8:a:b00:0:0:0:9%eth0", "2001:db8:a:b42::1.2.3.4"];
  for (const ip of same) assert.equal(ipBucket(ip), "2001:db8:a:b00::/56", ip);
});

test("ipBucket: the next /56 is a different bucket; :: forms expand before truncating", () => {
  assert.equal(ipBucket("2001:db8:a:c00::1"), "2001:db8:a:c00::/56");
  assert.equal(ipBucket("2001:db8:a:aff::1"), "2001:db8:a:a00::/56");
  assert.equal(ipBucket("2001:db8::1"), "2001:db8:0:0::/56");
  assert.equal(ipBucket("::1"), "0:0:0:0::/56");
  assert.equal(ipBucket("fe80::1%en0"), "fe80:0:0:0::/56");
  assert.equal(ipBucket("1:2:3:4:5:6:1.2.3.4"), "1:2:3:0::/56");   // an embedded IPv4 is TWO groups
});

test("ipBucket: IPv4 (and IPv4-mapped IPv6) stays the whole address (/32)", () => {
  assert.equal(ipBucket("203.0.113.7"), "203.0.113.7");
  assert.equal(ipBucket("203.0.113.8"), "203.0.113.8");
  assert.equal(ipBucket("203.0.113.007"), "203.0.113.7");   // leading zeros: same address, same key
  assert.equal(ipBucket("::ffff:203.0.113.7"), "203.0.113.7");
  assert.equal(ipBucket("::FFFF:203.0.113.7"), "203.0.113.7");
  assert.equal(ipBucket("0:0:0:0:0:ffff:203.0.113.7"), "203.0.113.7");   // non-canonical mapped forms
  assert.equal(ipBucket("::ffff:cb00:7107"), "203.0.113.7");
});

test("ipBucket: no header and garbage share fail-closed buckets", () => {
  assert.equal(ipBucket(null), "noip");
  assert.equal(ipBucket(""), "noip");
  for (const bad of ["1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3", "zz::1", "12345::1", "1:2:3:4:5:6:7:8::", "1:2:3:4:5:6:7:8::9::a",
    "not-an-ip", "1.2.3", "1.2.3.4.5", "evil-1", "evil-2", "999.1.1.1", "1.2.3.04x", "a:b@example.com#", "x:y@[2001:db8:ff::", "::1]/x", "::1]@[::2", "1::2]@[3::4"]) {
    assert.equal(ipBucket(bad), "badip", bad);
  }
});
