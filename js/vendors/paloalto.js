/*
 * Palo Alto Networks PAN-OS
 * Rules: PAN-OS 10.1+ IKE/IPsec crypto profile docs and IKEv2 liveness check (verified 2026-10-19).
 */
(function () {
  "use strict";
  const { isGcm, spell, intLabel, ALL } = TM;

  const N = {
    enc: { aes128: "aes-128-cbc", aes192: "aes-192-cbc", aes256: "aes-256-cbc", aes128gcm: "aes-128-gcm", aes256gcm: "aes-256-gcm", "3des": "3des" },
    int: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    dh: (n) => "group" + n,
    pfs: (n) => (n ? "group" + n : "no-pfs"),
  };

  /* With IKE AES-GCM, PAN-OS uses authentication non-auth and picks the PRF from the DH group. */
  const gcmPrf = (dh) => (dh <= 19 ? "sha256" : dh === 20 ? "sha384" : null);

  function generate(c) {
    const S = c.S;
    const g1 = isGcm(S.p1enc), g2 = isGcm(S.p2enc);
    const n = c.name;
    const tun = c.me.tun || "tunnel.10";
    const wan = c.me.iface || "ethernet1/1";
    const ike = `set network ike crypto-profiles ike-crypto-profiles IKE-${n}`;
    const ips = `set network ike crypto-profiles ipsec-crypto-profiles IPSEC-${n}`;
    const gw = `set network ike gateway GW-${n}`;
    const tn = `set network tunnel ipsec TUN-${n}`;

    const L = [
      `# PAN-OS set commands, site ${c.k}. Adjust zone and virtual/logical router to your setup.`,
      `${ike} encryption ${N.enc[S.p1enc]}`,
      `${ike} hash ${g1 ? "non-auth   # required with GCM; PRF follows the DH group" : N.int[S.p1int]}`,
      `${ike} dh-group ${N.dh(S.dh)}`,
      `${ike} lifetime seconds ${S.p1life}`,
      `${ips} esp encryption ${N.enc[S.p2enc]}`,
      `${ips} esp authentication ${g2 ? "none" : N.int[S.p2int]}`,
      `${ips} dh-group ${N.pfs(S.pfs)}`,
      `${ips} lifetime seconds ${S.p2life}`,
    ];
    if (S.p2kb) L.push(`${ips} lifesize kb ${S.p2kb}`);
    L.push(
      `set network interface tunnel units ${tun} comment "${c.peer.name}"`,
      `${gw} protocol version ikev2`,
      `${gw} protocol ikev2 ike-crypto-profile IKE-${n}`,
      `${gw} protocol ikev2 dpd enable yes`,
      `${gw} protocol ikev2 dpd interval ${S.dpdInt}`,
      // without it PAN-OS answers NO_PROPOSAL_CHOSEN to peers that start on UDP 4500 (RouterOS does)
      `${gw} protocol-common nat-traversal enable yes`,
      `${gw} authentication pre-shared-key key "${TM.PSK}"`,
      `${gw} local-address interface ${wan}`,
      `${gw} peer-address ip ${c.peer.ip}`,
      `${tn} auto-key ike-gateway GW-${n}`,
      `${tn} auto-key ipsec-crypto-profile IPSEC-${n}`,
      `${tn} tunnel-interface ${tun}`
    );
    if (!c.anyAny) {
      L.push("# One proxy-ID per subnet pair (required toward a policy-based peer)");
      c.pairs.forEach(([l, r], i) =>
        L.push(`${tn} auto-key proxy-id PID-${i + 1} local ${l.text} remote ${r.text} protocol any`));
    }
    L.push("# Static routes (legacy virtual router; with Advanced Routing use: set network logical-router ...)");
    c.remote.forEach((r, i) =>
      L.push(`set network virtual-router default routing-table ip static-route R-${n}-${i + 1} destination ${r.text} interface ${tun}`));
    return L.join("\n");
  }

  function checks({ S, k, add }) {
    if (!isGcm(S.p1enc)) return;
    const prf = gcmPrf(S.dh);
    if (S.p1enc === "aes128gcm" && S.dh !== 19)
      add("err", `PAN-OS (site ${k}): IKE aes-128-gcm requires DH group 19.`, "crypto");
    if (S.p1enc === "aes256gcm" && S.dh !== 20)
      add("warn", `PAN-OS (site ${k}): IKE aes-256-gcm should be paired with DH group 20.`, "crypto");
    if (prf && prf !== S.p1int)
      add("err", `PAN-OS (site ${k}) sets authentication to non-auth with IKE GCM and derives the PRF from the DH group (${intLabel(prf)} for group ${S.dh}). Set the PRF to ${intLabel(prf)} so the peer matches.`, "crypto");
    if (!prf)
      add("warn", `PAN-OS (site ${k}): the PRF used for IKE GCM with DH group ${S.dh} is not documented. Use group 19 or 20.`, "crypto");
  }

  function notes({ add }) {
    add("info", "PAN-OS with IKEv2 uses a liveness check: the interval is configurable (default 5 s) and the firewall retransmits up to 10 times. The retry count is not configurable.");
  }

  TM.register({
    id: "paloalto",
    order: 2,
    label: "Palo Alto Networks PAN-OS",
    short: "PAN-OS",
    modes: ["route"],
    narrow: true, // proxy-IDs
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: [2, 5, 14, 15, 19, 20, 21],
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0, 2, 5, 14, 15, 19, 20, 21],
    },
    verify: { dh: [15, 21], pfs: [15, 21] },
    verifyNote: "DH groups 15, 16 and 21 require PAN-OS 10.2 or later.",
    defaults: { iface: "ethernet1/1", tun: "tunnel.10" },
    fields: { iface: "WAN interface", tun: "Tunnel interface" },
    names: (S) => {
      const p = gcmPrf(S.dh);
      return {
        p1enc: spell(N.enc, S.p1enc),
        p1int: isGcm(S.p1enc) ? `non-auth (PRF ${p || "?"})` : spell(N.int, S.p1int),
        dh: N.dh(S.dh),
        p2enc: spell(N.enc, S.p2enc),
        p2int: isGcm(S.p2enc) ? "none" : spell(N.int, S.p2int),
        pfs: N.pfs(S.pfs),
        dpd: `interval ${S.dpdInt}`,
      };
    },
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-19",
      used: "IKE and IPsec crypto profile options, GCM requiring non-auth with the PRF taken from the DH group, aes-128-gcm with group 19, groups 15/16/21 needing PAN-OS 10.2+ and IKEv2, IKEv2 liveness check (5 s default, up to 10 retransmits).",
      links: [
        ["Define IKE Crypto Profiles (PAN-OS 10.1 and later)", "https://docs.paloaltonetworks.com/content/techdocs/en_US/network-security/ipsec-vpn/administration/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ike-crypto-profiles-pan-os-10-1.html"],
        ["Define IPSec Crypto Profiles (PAN-OS 10.1 and later)", "https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/set-up-site-to-site-vpn/define-cryptographic-profiles/define-ipsec-crypto-profiles-pan-os-10-1"],
        ["IPSec Crypto profile fields (ESP authentication none)", "https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-web-interface-help/network/network-network-profiles/network-network-profiles-ipsec-crypto"],
        ["IKEv2 liveness check", "https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-admin/vpns/site-to-site-vpn-concepts/ikev2/liveness-check"],
      ],
    },
  });
})();
