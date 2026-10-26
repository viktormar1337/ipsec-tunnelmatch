/*
 * MikroTik RouterOS 7 (CHR and hardware)
 * Rules: RouterOS CLI reference for /ip ipsec profile and /ip ipsec proposal ("Version:
 * current", checked 2026-10-20) and the RouterOS IPsec manual (peers, identities,
 * policies, NAT bypass).
 *
 * Policy-based only: RouterOS has no VTI. IKE (profile) has no AES-GCM; ESP (proposal)
 * has no HMAC-SHA-384. The profile's lifetime and dpd-maximum-failures are documented as
 * IKEv1-only; they are still written so the values are on record.
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    enc1: { aes128: "aes-128", aes192: "aes-192", aes256: "aes-256", "3des": "3des" },
    enc2: { aes128: "aes-128-cbc", aes192: "aes-192-cbc", aes256: "aes-256-cbc", aes128gcm: "aes-128-gcm", aes256gcm: "aes-256-gcm", "3des": "3des" },
    hash: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    auth: { sha1: "sha1", sha256: "sha256", sha512: "sha512", md5: "md5" },
    dh: { 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 19: "ecp256", 20: "ecp384", 21: "ecp521" },
  };

  /* RouterOS time values: 28800 -> 8h, 3600 -> 1h, 90 -> 90s */
  function rosTime(sec) {
    if (sec % 86400 === 0) return `${sec / 86400}d`;
    if (sec % 3600 === 0) return `${sec / 3600}h`;
    if (sec % 60 === 0) return `${sec / 60}m`;
    return `${sec}s`;
  }

  function generate(c) {
    const S = c.S;
    const n = c.name.toLowerCase();
    const prof = `tm-${n}`;
    const pairs = c.anyAny ? [[{ text: "0.0.0.0/0" }, { text: "0.0.0.0/0" }]] : c.pairs;
    const q = (s) => `"${s}"`;

    const L = [
      `# MikroTik RouterOS 7, site ${c.k}. Paste in a terminal (CLI), section by section.`,
      "/ip ipsec profile",
      `add name=${prof} enc-algorithm=${N.enc1[S.p1enc]} hash-algorithm=${N.hash[S.p1int]} prf-algorithm=${N.hash[S.p1int]} \\`,
      `    dh-group=${N.dh[S.dh]} lifetime=${rosTime(S.p1life)} dpd-interval=${S.dpdInt}s dpd-maximum-failures=${S.dpdRetry} nat-traversal=yes`,
      "/ip ipsec peer",
      `add name=${n} address=${c.peer.ip}/32 local-address=${c.me.ip} exchange-mode=ike2 profile=${prof}`,
      "/ip ipsec identity",
      // my-id=auto sends the local-address (the same ID); with an explicit my-id RouterOS 7.24.5 as
      // responder rejects initiators that send no IDr (PAN-OS) with "identity not found"
      `add peer=${n} auth-method=pre-shared-key secret=${q(TM.PSK)} my-id=auto remote-id=address:${c.peer.ip} generate-policy=no`,
      "/ip ipsec proposal",
      `add name=${prof} enc-algorithms=${N.enc2[S.p2enc]} auth-algorithms=${isGcm(S.p2enc) ? '""' : N.auth[S.p2int]} \\`,
      `    pfs-group=${S.pfs ? N.dh[S.pfs] : "none"} lifetime=${rosTime(S.p2life)}`,
      "/ip ipsec policy",
      ...pairs.map(([l, r]) =>
        `add peer=${n} tunnel=yes src-address=${l.text} dst-address=${r.text} proposal=${prof} action=encrypt level=unique`),
      "# Exempt the tunnel traffic from masquerade/srcnat. Move these rules above any masquerade",
      "# rule (in WinBox, or with move); place-before=0 fails on an empty NAT table.",
      "/ip firewall nat",
      ...pairs.map(([l, r]) =>
        `add chain=srcnat action=accept src-address=${l.text} dst-address=${r.text} comment=${q("IPsec " + n)}`),
      "# If the input chain drops by default: allow IKE, NAT-T and ESP from the peer,",
      "# and move these rules above the drop rule.",
      "/ip firewall filter",
      `add chain=input action=accept protocol=udp src-address=${c.peer.ip} dst-port=500,4500 comment=${q("IKE " + n)}`,
      `add chain=input action=accept protocol=ipsec-esp src-address=${c.peer.ip} comment=${q("ESP " + n)}`,
    ];
    if (pairs.length > 1)
      L.push("# level=unique gives every policy its own child SA toward the same peer.");
    return L.join("\n");
  }

  function notes({ add }) {
    add("info", "MikroTik RouterOS: policy-based only (no VTI). RouterOS documents the profile's lifetime and dpd-maximum-failures as IKEv1-only, so with IKEv2 the peer's IKE rekey timer and RouterOS's own DPD retries apply.");
  }

  TM.register({
    id: "mikrotik",
    order: 10,
    label: "MikroTik RouterOS 7",
    short: "MikroTik",
    modes: ["policy"],
    narrow: false,
    multiSaNote: true, // one child SA per policy (level=unique)
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "3des"],
      p1int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      dh: [2, 5, 14, 15, 19, 20, 21],
      p2enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p2int: ["sha1", "sha256", "sha512", "md5"],
      pfs: [0, 2, 5, 14, 15, 19, 20, 21],
    },
    defaults: {},
    fields: {},
    hint: "RouterOS has no VTI, so this side is policy-based. Phase 1 has no AES-GCM; phase 2 has no SHA-384.",
    names: (S) => ({
      p1enc: spell(N.enc1, S.p1enc),
      p1int: `hash/prf ${spell(N.hash, S.p1int)}`,
      dh: spell(N.dh, S.dh),
      p2enc: spell(N.enc2, S.p2enc),
      p2int: isGcm(S.p2enc) ? "none (GCM: auth-algorithms=\"\")" : spell(N.auth, S.p2int),
      pfs: S.pfs ? spell(N.dh, S.pfs) : "none",
      dpd: `dpd-interval=${S.dpdInt}s dpd-maximum-failures=${S.dpdRetry}`,
    }),
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-20",
      used: "Profile options (enc-algorithm AES-CBC/3DES only, hash and prf-algorithm up to SHA-512, DH modp768–8192 and ecp256/384/521, lifetime and dpd-maximum-failures documented as IKEv1-only), proposal options (AES-CBC/CTR/GCM, auth up to SHA-512 without SHA-384, PFS groups), peers with exchange-mode=ike2, identities with my-id/remote-id, policies with level=unique, and the srcnat bypass for site-to-site. AES-GCM in phase 2 is generated with an empty auth-algorithms=\"\": RouterOS 7.24.5 rejects auth-algorithms=null and the default sha1 with \"AEAD already provides authentication\" (GNS3 lab, CHR 7.24.5). The identity uses my-id=auto (the local-address): with an explicit my-id, CHR 7.24.5 as responder rejected PAN-OS 12.2, which sends no IDr, with \"identity not found\" (GNS3 lab).",
      links: [
        ["MikroTik CLI reference: /ip ipsec profile", "https://manual.mikrotik.com/docs/cli-reference/ip/ipsec/profile"],
        ["MikroTik CLI reference: /ip ipsec proposal", "https://manual.mikrotik.com/docs/cli-reference/ip/ipsec/proposal"],
        ["MikroTik RouterOS manual: IPsec", "https://help.mikrotik.com/docs/spaces/ROS/pages/11993097/IPsec"],
      ],
    },
  });
})();
