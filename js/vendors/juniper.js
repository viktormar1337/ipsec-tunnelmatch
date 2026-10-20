/*
 * Juniper SRX (Junos)
 * Rules: Junos CLI reference for security ike proposal, encryption-algorithm,
 * dh-group, security ipsec proposal, dead-peer-detection, and traffic selectors
 * in route-based VPNs (verified 2026-10-20).
 *
 * Always generated route-based (st0 interface). Toward a policy-based peer the
 * VPN gets one traffic-selector per subnet pair, which is Juniper's recommended
 * way to match it; routes are then added automatically (auto route insertion).
 */
(function () {
  "use strict";
  const { isGcm, spell, ALL } = TM;

  const N = {
    enc: { aes128: "aes-128-cbc", aes192: "aes-192-cbc", aes256: "aes-256-cbc", aes128gcm: "aes-128-gcm", aes256gcm: "aes-256-gcm", "3des": "3des-cbc" },
    ikeInt: { sha1: "sha1", sha256: "sha-256", sha384: "sha-384", sha512: "sha-512", md5: "md5" },
    espInt: { sha1: "hmac-sha1-96", sha256: "hmac-sha-256-128", sha384: "hmac-sha-384", sha512: "hmac-sha-512", md5: "hmac-md5-96" },
    dh: (n) => "group" + n,
  };

  /* Values that exist only on some Junos releases or platforms. */
  const REMOVED_25_2 = ["3des", "sha1", "md5", 2, 5];
  function verifyNote(field, value) {
    if (REMOVED_25_2.includes(value))
      return "removed in Junos 25.2R1 (marked NOT RECOMMENDED since 20.2R1).";
    if (value === 15 || value === 21)
      return "groups 15, 16 and 21 need the junos-ike package (SRX5000 from 19.1R1, vSRX from 20.3R1).";
    if (field === "p1int")
      return "SHA-512 in an IKE proposal is only listed for newer Junos releases; check your platform and release.";
    return "HMAC-SHA-384/512 for ESP came in Junos 19.1R1 (first on SRX5000 with SPC3); check your platform and release.";
  }

  /* "st0.0" -> { ifl: "st0.0", unit: "0" } */
  function tunnelUnit(value) {
    const ifl = (value || "st0.0").trim() || "st0.0";
    const unit = ifl.includes(".") ? ifl.split(".").pop() : "0";
    return { ifl: ifl.includes(".") ? ifl : `st0.${unit}`, unit };
  }

  function generate(c) {
    const S = c.S;
    const g1 = isGcm(S.p1enc), g2 = isGcm(S.p2enc);
    const n = c.name;
    const wan = c.me.iface || "ge-0/0/0.0";
    const { ifl, unit } = tunnelUnit(c.me.tun);
    const ike = `set security ike proposal IKE-${n}`;
    const ikePol = `set security ike policy IKE-POL-${n}`;
    const gw = `set security ike gateway GW-${n}`;
    const ips = `set security ipsec proposal IPSEC-${n}`;
    const ipsPol = `set security ipsec policy IPSEC-POL-${n}`;
    const vpn = `set security ipsec vpn VPN-${n}`;

    const L = [
      `# Junos set commands, side ${c.k}. Adjust interfaces, zones and policies to your setup.`,
      "# Phase 1",
      `${ike} authentication-method pre-shared-keys`,
      `${ike} dh-group ${N.dh(S.dh)}`,
    ];
    if (g1) L.push("# AES-GCM in IKE: no authentication-algorithm; Junos selects the PRF itself.");
    else L.push(`${ike} authentication-algorithm ${N.ikeInt[S.p1int]}`);
    L.push(
      `${ike} encryption-algorithm ${N.enc[S.p1enc]}`,
      `${ike} lifetime-seconds ${S.p1life}`,
      `${ikePol} proposals IKE-${n}`,
      `${ikePol} pre-shared-key ascii-text "${TM.PSK}"`,
      `${gw} ike-policy IKE-POL-${n}`,
      `${gw} address ${c.peer.ip}`,
      `${gw} external-interface ${wan}`,
      `${gw} version v2-only`,
      `${gw} dead-peer-detection interval ${S.dpdInt}`,
      `${gw} dead-peer-detection threshold ${S.dpdRetry}`,
      "# Phase 2",
      `${ips} protocol esp`
    );
    if (!g2) L.push(`${ips} authentication-algorithm ${N.espInt[S.p2int]}`);
    L.push(`${ips} encryption-algorithm ${N.enc[S.p2enc]}`, `${ips} lifetime-seconds ${S.p2life}`);
    if (S.p2kb >= 64000) L.push(`${ips} lifetime-kilobytes ${S.p2kb}`);
    L.push(`${ipsPol} proposals IPSEC-${n}`);
    if (S.pfs) L.push(`${ipsPol} perfect-forward-secrecy keys ${N.dh(S.pfs)}`);
    L.push(
      `${vpn} bind-interface ${ifl}`,
      `${vpn} ike gateway GW-${n}`,
      `${vpn} ike ipsec-policy IPSEC-POL-${n}`,
      `${vpn} establish-tunnels immediately`
    );

    if (!c.anyAny) {
      L.push("# One traffic selector per subnet pair (matches a policy-based peer).",
        "# Routes to the remote networks are added automatically (auto route insertion).");
      c.pairs.forEach(([l, r], i) =>
        L.push(`${vpn} traffic-selector TS-${i + 1} local-ip ${l.text} remote-ip ${r.text}`));
    }

    L.push(
      "# Tunnel interface and zone",
      `set interfaces st0 unit ${unit} family inet`,
      `set security zones security-zone vpn interfaces ${ifl}`
    );
    if (c.anyAny) {
      L.push("# Static routes to the remote networks");
      c.remote.forEach((r) => L.push(`set routing-options static route ${r.text} next-hop ${ifl}`));
    }

    L.push("# Address book and security policies (trust <-> vpn)");
    c.local.forEach((l, i) => L.push(`set security address-book global address LOCAL-${n}-${i + 1} ${l.text}`));
    c.remote.forEach((r, i) => L.push(`set security address-book global address REMOTE-${n}-${i + 1} ${r.text}`));
    const policy = (from, to, name, src, dst) => {
      const p = `set security policies from-zone ${from} to-zone ${to} policy ${name}`;
      src.forEach((s) => L.push(`${p} match source-address ${s}`));
      dst.forEach((d) => L.push(`${p} match destination-address ${d}`));
      L.push(`${p} match application any`, `${p} then permit`);
    };
    const locals = c.local.map((_, i) => `LOCAL-${n}-${i + 1}`);
    const remotes = c.remote.map((_, i) => `REMOTE-${n}-${i + 1}`);
    policy("trust", "vpn", `TO-${n}`, locals, remotes);
    policy("vpn", "trust", `FROM-${n}`, remotes, locals);
    L.push("# Allow IKE on the external interface's zone: set security zones security-zone untrust host-inbound-traffic system-services ike");
    return L.join("\n");
  }

  function checks({ S, k, add }) {
    if (S.p1life < 180 || S.p1life > 86400) add("err", `Juniper SRX (side ${k}): IKE lifetime-seconds must be 180–86400.`);
    if (S.p2life < 180 || S.p2life > 86400) add("err", `Juniper SRX (side ${k}): IPsec lifetime-seconds must be 180–86400.`);
    if (S.p2kb && S.p2kb < 64000) add("err", `Juniper SRX (side ${k}): lifetime-kilobytes must be at least 64000 (or 0 to leave it unset).`);
    if (S.dpdInt < 2 || S.dpdInt > 60) add("err", `Juniper SRX (side ${k}): dead-peer-detection interval must be 2–60 s.`);
    if (S.dpdRetry > 5) add("err", `Juniper SRX (side ${k}): dead-peer-detection threshold must be 1–5.`);
    if (isGcm(S.p1enc)) {
      add("warn", `Juniper SRX (side ${k}): with AES-GCM in IKE, Junos takes no authentication-algorithm and selects the PRF itself. Check that the negotiated PRF matches the peer (show security ike security-associations detail), or use AES-CBC in IKE.`, "crypto");
      if (!isGcm(S.p2enc))
        add("warn", `Juniper SRX (side ${k}): when IKE uses AES-GCM, Junos expects AES-GCM in the IPsec proposal as well.`, "crypto");
    }
  }

  function notes({ S, add }) {
    if (S.p2kb) add("info", "Juniper SRX: lifetime-kilobytes is supported with iked from Junos 23.4R1; on older releases leave it unset.");
  }

  TM.register({
    id: "juniper",
    order: 7,
    label: "Juniper SRX (Junos)",
    short: "Juniper SRX",
    modes: ["route"],
    narrow: true, // traffic-selector per subnet pair
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: ALL.dh,
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0].concat(ALL.dh),
    },
    verify: {
      p1enc: ["3des"],
      p2enc: ["3des"],
      p1int: ["sha1", "md5", "sha512"],
      p2int: ["sha1", "md5", "sha384", "sha512"],
      dh: [2, 5, 15, 21],
      pfs: [2, 5, 15, 21],
    },
    verifyNote,
    defaults: { iface: "ge-0/0/0.0", tun: "st0.0" },
    fields: { iface: "External interface", tun: "Tunnel interface (st0)" },
    hint: "Generated route-based on st0. Toward a policy-based peer, one traffic-selector per subnet pair is added automatically.",
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: isGcm(S.p1enc) ? "(none, PRF selected by Junos)" : spell(N.ikeInt, S.p1int),
      dh: N.dh(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(none, GCM)" : spell(N.espInt, S.p2int),
      pfs: S.pfs ? "keys " + N.dh(S.pfs) : "(no PFS)",
      dpd: `dead-peer-detection interval ${S.dpdInt} threshold ${S.dpdRetry}`,
    }),
    narrowNote: "Junos: one traffic-selector per subnet pair; routes are added by auto route insertion.",
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-20",
      used: "IKE and IPsec proposal options (AES-CBC/GCM, SHA-256/384/512, DH 14–24), GCM rules (IKEv2 only, no IKE authentication-algorithm), algorithms removed in 25.2R1, junos-ike requirement for groups 15/16/21, lifetimes 180–86400 s, lifetime-kilobytes ≥ 64000, DPD interval 2–60 s and threshold 1–5, traffic selectors with auto route insertion.",
      links: [
        ["Junos CLI: proposal (Security IKE)", "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-proposal.html"],
        ["Junos CLI: encryption-algorithm (Security IKE)", "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/encryption-algorithm-edit-security-ike.html"],
        ["Junos CLI: dh-group (Security IKE)", "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-dh-group.html"],
        ["Junos CLI: proposal (Security IPsec)", "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/proposal-edit-security-ipsec.html"],
        ["Junos CLI: dead-peer-detection", "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-dead-peer-detection.html"],
        ["Junos: Traffic selectors in route-based VPNs", "https://juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-traffic-selectors-in-route-based-vpns.html"],
        ["Junos: Route-based IPsec VPNs", "https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-route-based-ipsec-vpns.html"],
      ],
    },
  });
})();
