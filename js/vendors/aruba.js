/*
 * HPE Aruba Networking gateways / Mobility Controllers (ArubaOS 8.x, AOS 10 gateways)
 * Rules: AOS 8 CLI reference (CLI-Bank), "crypto isakmp policy", "crypto ipsec transform-set",
 * "crypto-local ipsec-map" and "crypto-local isakmp key", checked 2026-10-21. AOS 10 site-to-site
 * in Central offers the same groups and lifetime range.
 *
 * IKE: AES-CBC and 3DES only (no GCM), hash up to SHA2-384, groups 1/2/14/19/20.
 * ESP: AES-CBC, AES-GCM-128/256; SHA2-256 integrity from 8.13.0, SHA2-384/512 from 8.13.2.
 * SHA2, groups 19/20 and GCM need the Advanced Cryptography (ACR) licence on AOS 8.
 * Site-to-site with a third party is an ipsec-map per subnet pair (policy-based).
 * The DPD command line below is not from the reference page; check it on your release.
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    ikeEnc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", "3des": "3des" },
    ikeHash: { sha1: "sha", sha256: "sha2-256-128", sha384: "sha2-384-192", md5: "md5" },
    prf: { sha1: "PRF-HMAC-SHA1", sha256: "PRF-HMAC-SHA256", sha384: "PRF-HMAC-SHA384", md5: "PRF-HMAC-MD5" },
    espEnc: { aes128: "esp-aes128", aes192: "esp-aes192", aes256: "esp-aes256", aes128gcm: "esp-aes128-gcm", aes256gcm: "esp-aes256-gcm", "3des": "esp-3des" },
    espHash: { sha1: "esp-sha-hmac", sha256: "esp-sha2-256-hmac", sha384: "esp-sha2-384-hmac", sha512: "esp-sha2-512-hmac", md5: "esp-md5-hmac" },
  };
  const ACR = (S) =>
    S.p1int !== "sha1" && S.p1int !== "md5" || [19, 20].includes(S.dh) || [19, 20].includes(S.pfs) ||
    isGcm(S.p2enc) || (!isGcm(S.p2enc) && !["sha1", "md5"].includes(S.p2int));

  const mask = (len) => {
    const n = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
    return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
  };
  const net = (t) => {
    const [ip, l] = String(t).split("/");
    return `${ip} ${mask(l === undefined ? 32 : Number(l))}`;
  };

  function generate(c) {
    const S = c.S;
    const prio = 100;
    const ts = `TS-${c.name}`;
    const pairs = c.anyAny ? [[{ text: "0.0.0.0/0" }, { text: "0.0.0.0/0" }]] : c.pairs;
    const vlan = (c.me.iface || "").replace(/\D/g, "") || "4094";
    const L = [
      `! ArubaOS 8 / AOS 10 gateway, site ${c.k}. configure terminal, paste, write memory.`,
      `crypto isakmp policy ${prio}`,
      "  version v2",
      "  authentication pre-share",
      `  encryption ${N.ikeEnc[S.p1enc]}`,
      `  hash ${N.ikeHash[S.p1int]}`,
      `  prf ${N.prf[S.p1int]}`,
      `  group ${S.dh}`,
      `  lifetime ${S.p1life}`,
      "!",
      `crypto ipsec transform-set ${ts} ${N.espEnc[S.p2enc]}${isGcm(S.p2enc) ? "" : " " + N.espHash[S.p2int]}`,
      "!",
      `crypto-local isakmp key ${TM.PSK} address ${c.peer.ip} netmask 255.255.255.255`,
      `! DPD (check the syntax on your release): crypto-local isakmp dpd idle-timeout ${S.dpdInt} retry-timeout ${S.dpdInt} retry-attempts ${S.dpdRetry}`,
      "!",
    ];
    pairs.forEach(([l, r], i) => {
      L.push(
        `crypto-local ipsec-map ${c.name}${pairs.length > 1 ? "-" + (i + 1) : ""} ${prio + i}`,
        "  version v2",
        `  peer-ip ${c.peer.ip}`,
        `  vlan ${vlan}`,
        `  src-net ${net(l.text)}`,
        `  dst-net ${net(r.text)}`,
        `  set ikev2-policy ${prio}`,
        `  set transform-set ${ts}`,
        ...(S.pfs ? [`  set pfs group${S.pfs}`] : []),
        `  set security-association lifetime seconds ${S.p2life}`,
        "  pre-connect enable",
        "  trusted enable",
        "!"
      );
    });
    L.push(
      "! The vlan is the uplink VLAN that carries " + c.me.ip + ".",
      "! Allow the remote subnets in the session ACL / user role used on the LAN side,",
      "! and leave the tunnel traffic out of any source NAT on the uplink."
    );
    return L.join("\n");
  }

  function checks({ S, k, add }) {
    for (const [what, v] of [["IKE lifetime", S.p1life], ["IPsec SA lifetime", S.p2life]])
      if (v < 300 || v > 86400) add("err", `Aruba (site ${k}): ${what} must be 300–86400 s.`);
  }

  function notes({ S, add }) {
    if (ACR(S)) add("info", "Aruba AOS 8: SHA2, DH 19/20 and AES-GCM need the Advanced Cryptography (ACR) licence.");
    if (!isGcm(S.p2enc) && ["sha384", "sha512"].includes(S.p2int))
      add("warn", "Aruba: ESP SHA2-384/512 needs ArubaOS 8.13.2 or later (SHA2-256 needs 8.13.0).");
    else if (!isGcm(S.p2enc) && S.p2int === "sha256")
      add("info", "Aruba: ESP SHA2-256 integrity needs ArubaOS 8.13.0 or later.");
  }

  TM.register({
    id: "aruba",
    order: 15,
    label: "HPE Aruba gateway (AOS 8 / AOS 10)",
    short: "Aruba",
    modes: ["policy"],
    narrow: true,
    multiSaNote: true,
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "3des"],
      p1int: ["sha1", "sha256", "sha384", "md5"],
      dh: [2, 14, 19, 20],
      p2enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p2int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      pfs: [0, 2, 14, 19, 20],
    },
    defaults: { iface: "4094" },
    fields: { iface: "Uplink VLAN ID" },
    hint: "One ipsec-map per subnet pair. No GCM in IKE; DH 2, 14, 19, 20 only.",
    names: (S) => ({
      p1enc: spell(N.ikeEnc, S.p1enc),
      p1int: `${spell(N.ikeHash, S.p1int)}, prf ${spell(N.prf, S.p1int)}`,
      dh: `group ${S.dh}`,
      p2enc: spell(N.espEnc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM)" : spell(N.espHash, S.p2int),
      pfs: S.pfs ? `group${S.pfs}` : "off",
      dpd: `idle ${S.dpdInt} s, ${S.dpdRetry} retries`,
    }),
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-21",
      used: "AOS 8 CLI reference: isakmp policy values (encryption, hash, prf, group 1/2/14/19/20, lifetime 300–86400 s, ACR licence), transform-set values incl. GCM and the 8.13 SHA2 additions, ipsec-map fields (peer-ip, src-net/dst-net, ikev2-policy, pfs, SA lifetime, pre-connect, trusted) and the PSK command. The DPD line is not from these pages.",
      links: [
        ["AOS 8 CLI: crypto isakmp policy", "https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/cr-isakmp-policy.htm"],
        ["AOS 8 CLI: crypto ipsec transform-set", "https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/cr-ipsec-transform.htm"],
        ["AOS 8 CLI: crypto-local ipsec-map", "https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/aos8/crypto-local-ipsec-map.htm"],
      ],
    },
  });
})();
