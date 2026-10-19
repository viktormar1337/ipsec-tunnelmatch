/*
 * IPsec Tunnelmatch – shared core
 *
 * Everything vendor files and the app need in common:
 *   - the neutral algorithm catalog (ids used everywhere internally)
 *   - small helpers for networks, escaping and naming
 *   - the vendor registry (TM.register / TM.vendor / TM.vendorIds)
 *
 * Plain scripts (no modules) so the tool also runs from a local file.
 */
window.TM = (function () {
  "use strict";

  /* ---------- algorithm catalog ---------- */

  const ENC = [
    ["aes128", "AES-128-CBC"],
    ["aes192", "AES-192-CBC"],
    ["aes256", "AES-256-CBC"],
    ["aes128gcm", "AES-128-GCM"],
    ["aes256gcm", "AES-256-GCM"],
    ["3des", "3DES"],
  ];

  const INT = [
    ["sha1", "SHA-1"],
    ["sha256", "SHA-256"],
    ["sha384", "SHA-384"],
    ["sha512", "SHA-512"],
    ["md5", "MD5"],
  ];

  const DH = [
    [2, "Group 2 · MODP 1024"],
    [5, "Group 5 · MODP 1536"],
    [14, "Group 14 · MODP 2048"],
    [15, "Group 15 · MODP 3072"],
    [19, "Group 19 · ECP 256"],
    [20, "Group 20 · ECP 384"],
    [21, "Group 21 · ECP 521"],
    [24, "Group 24 · MODP 2048/256"],
  ];

  const PFS = [[0, "No PFS"]].concat(DH);

  /* Algorithms flagged as weak or deprecated, whatever the platform. */
  const LEGACY = { enc: ["3des"], int: ["md5", "sha1"], dh: [2, 5] };

  const ALL = {
    enc: ENC.map((x) => x[0]),
    int: INT.map((x) => x[0]),
    dh: DH.map((x) => x[0]),
  };

  const isGcm = (enc) => enc.endsWith("gcm");
  const encLabel = (id) => (ENC.find((x) => x[0] === id) || [, id])[1];
  const intLabel = (id) => (INT.find((x) => x[0] === id) || [, id])[1];
  const dhLabel = (n) => (n === 0 ? "None" : "Group " + n);

  /* Look a value up in a vendor's spelling table (object or function). */
  function spell(table, value) {
    if (!table) return "–";
    const r = typeof table === "function" ? table(value) : table[value];
    return r == null ? "(not supported)" : r;
  }

  /* ---------- networks ---------- */

  function parseCidr(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(s.trim());
    if (!m) return null;
    const o = m.slice(1, 5).map(Number);
    const prefix = +m[5];
    if (o.some((x) => x > 255) || prefix > 32) return null;
    const ip = ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { text: s.trim(), ip, prefix, mask, net: (ip & mask) >>> 0 };
  }

  const i2s = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const maskStr = (c) => i2s(c.mask);
  const wildcard = (c) => i2s(~c.mask >>> 0);
  const netStr = (c) => i2s(c.net);

  function overlap(a, b) {
    const m = Math.min(a.prefix, b.prefix);
    const mk = m === 0 ? 0 : (0xffffffff << (32 - m)) >>> 0;
    return ((a.net & mk) >>> 0) === ((b.net & mk) >>> 0);
  }

  function validIp(s) {
    const t = s.trim();
    return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(t) && t.split(".").every((x) => +x <= 255);
  }

  /* ---------- text helpers ---------- */

  const esc = (s) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const slug = (s) =>
    (s || "peer").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "peer";

  /* The pre-shared key is never collected; configs show this placeholder. */
  const PSK = "<PSK>";

  /* ---------- vendor registry ---------- */

  const vendors = {};

  function register(v) {
    v.verify = v.verify || {};
    v.fields = v.fields || {};
    v.defaults = v.defaults || {};
    vendors[v.id] = v;
  }

  const vendor = (id) => vendors[id];
  const vendorIds = () => Object.values(vendors).sort((a, b) => a.order - b.order).map((v) => v.id);

  return {
    ENC, INT, DH, PFS, LEGACY, ALL,
    isGcm, encLabel, intLabel, dhLabel, spell,
    parseCidr, i2s, maskStr, wildcard, netStr, overlap, validIp,
    esc, slug, PSK,
    register, vendor, vendorIds,
  };
})();
