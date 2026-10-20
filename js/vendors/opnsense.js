/*
 * OPNsense (Connections model) and pfSense (Tunnels model)
 * Syntax: OPNsense docs, IPsec route-based (VTI) PSK setup and VPN overview.
 * OPNsense proposals are strongSwan strings, but the field only accepts entries from a fixed
 * list (IPsecProposalField.php in opnsense/core). opnProposal() spells them the way that list
 * does and opnValid() reproduces how the list is built, so unlisted combinations are flagged.
 */
(function () {
  "use strict";
  const { isGcm, spell, ALL } = TM;

  /* pfSense GUI labels (Tunnels > Phase 1 / Phase 2). */
  const PF_DH = {
    2: "2 (1024 bits)", 5: "5 (1536 bits)", 14: "14 (2048 bits)", 15: "15 (3072 bits)",
    19: "19 (nist ecp256)", 20: "20 (nist ecp384)", 21: "21 (nist ecp521)", 24: "24 (2048(sub 256) bits)",
  };
  const PF = {
    enc: { aes128: "AES 128 bits", aes192: "AES 192 bits", aes256: "AES 256 bits", aes128gcm: "AES128-GCM16", aes256gcm: "AES256-GCM16", "3des": "3DES" },
    int: { sha1: "SHA1", sha256: "SHA256", sha384: "SHA384", sha512: "SHA512", md5: "MD5" },
    dh: (n) => PF_DH[n],
    pfs: (n) => (n ? PF_DH[n] : "off"),
  };

  /* OPNsense proposal spelling (IPsecProposalField). AEAD in phase 1 is enc-prf-dh with no
     "prf" prefix; in phase 2 GCM is enc-dh. */
  const O = {
    enc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm: "aes128gcm16", aes256gcm: "aes256gcm16", "3des": "3des" },
    int: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    dh: { 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 19: "ecp256", 20: "ecp384", 21: "ecp521", 24: "modp2048s256" },
  };
  const ike = (S) => `${O.enc[S.p1enc]}-${O.int[S.p1int]}-${O.dh[S.dh]}`;
  const esp = (S) =>
    `${O.enc[S.p2enc]}${isGcm(S.p2enc) ? "" : "-" + O.int[S.p2int]}${S.pfs ? "-" + O.dh[S.pfs] : ""}`;

  /* The generated part of the list: every enc x int x dh below, both phases. */
  const GEN = {
    enc: ["aes128", "aes192", "aes256", "aes128gcm16", "aes192gcm16", "aes256gcm16"],
    int: ["sha256", "sha384", "sha512", "aesxcbc"],
    dh: ["modp2048", "modp3072", "modp4096", "modp6144", "modp8192", "ecp224", "ecp256", "ecp384", "ecp521",
      "ecp224bp", "ecp256bp", "ecp384bp", "ecp512bp", "x25519", "x448"],
  };
  /* Fixed entries outside the generated grid (the "insecure" group and no-PFS entries). */
  const FIXED = {
    1: ["aes256-sha1-modp2048", "aes192-sha1-modp2048", "aes128-sha1-modp2048", "aes256-sha1-modp4096",
      "aes256-sha1-ecp521", "aes256-sha256-modp1024", "aes256-sha512-modp1024", "aes256-sha256-modp1536",
      "aes128-sha256-modp1536", "aes256gcm16-sha256-modp1536"],
    2: ["aes256-sha1-modp2048", "aes192-sha1-modp2048", "aes128-sha1-modp2048", "aes256-sha1-modp4096",
      "aes256-sha1-ecp521", "aes256-sha256-modp1024", "aes256-sha512-modp1024", "aes256-sha256-modp1536",
      "aes128-sha256-modp1536", "aes256gcm16-sha256-modp1536", "aes256gcm16", "aes256-sha1", "aes256-sha256"],
  };
  function opnValid(phase, str) {
    if (FIXED[phase].includes(str)) return true;
    const p = str.split("-");
    if (p.length === 3) return GEN.enc.includes(p[0]) && GEN.int.includes(p[1]) && GEN.dh.includes(p[2]);
    /* phase 2 AEAD without integrity: encgcm16-dh */
    return phase === 2 && p.length === 2 && p[0].includes("gcm") && GEN.enc.includes(p[0]) && GEN.dh.includes(p[1]);
  }

  function opnsense(c, kids) {
    const S = c.S;
    const route = c.eff.mode === "route";
    const reqid = (c.me.tun || "10").trim() || "10";
    const ikeP = ike(S), espP = esp(S);
    const step = (() => { let i = 0; return () => ++i; })();

    const psk = `${step()}. Pre-shared key ............ VPN > IPsec > Pre-Shared Keys > +
     Local Identifier ........ ${c.me.ip}
     Remote Identifier ....... ${c.peer.ip}
     Pre-Shared Key .......... ${TM.PSK}
`;

    const vti = route ? `
${step()}. Virtual tunnel interface .. VPN > IPsec > Virtual Tunnel Interfaces > +
     Reqid ................... ${reqid}
     Local address ........... ${c.me.ip}
     Remote address .......... ${c.peer.ip}
     Tunnel local address .... 169.254.${reqid}.1   (agree with the peer)
     Tunnel remote address ... 169.254.${reqid}.2
` : "";

    const children = kids.map(([l, r], i) => `   Child ${i + 1}
     Description ............. ${l.text} <> ${r.text}
     Mode .................... Tunnel
     Policies ................ ${route ? "unchecked (routing decides; never install policies on a VTI)" : "checked"}
${route ? `     Reqid ................... ${reqid}\n` : ""}     Local ................... ${l.text}
     Remote .................. ${r.text}
     ESP proposals ........... ${espP}
     Start action ............ ${route ? "Trap" : "Start"}
     Rekey time (s) .......... ${S.p2life}   (advanced mode)`).join("\n");

    const connection = `
${step()}. Connection ................ VPN > IPsec > Connections > +
   General settings
     Description ............. ${c.peer.name}
     Version ................. IKEv2
     Proposals ............... ${ikeP}   (remove the default first)
     Local addresses ......... ${c.me.ip}
     Remote addresses ........ ${c.peer.ip}
     Unique .................. Replace
     DPD delay (s) ........... ${S.dpdInt}
     Rekey time (s) .......... ${S.p1life}   (advanced mode)
   Local authentication > +
     Authentication .......... Pre-Shared Key
     Id ...................... ${c.me.ip}
   Remote authentication > +
     Authentication .......... Pre-Shared Key
     Id ...................... ${c.peer.ip}
   Children${kids.length > 1 ? ` (one per subnet pair, ${kids.length} in total)` : ""}
${children}
   Save, then Apply.
`;

    const routing = route ? `
${step()}. Gateway ................... System > Gateways > Configuration > +
     Name .................... IPSEC${reqid}_GW
     Interface ............... IPSEC${reqid}
     IP address .............. 169.254.${reqid}.2

${step()}. Routes .................... System > Routes > Configuration
${c.remote.map((r) => `     ${r.text.padEnd(20)} via IPSEC${reqid}_GW`).join("\n")}
` : "";

    const firewall = `
${step()}. Firewall .................. Firewall > Rules > IPsec: allow the tunnel traffic.

DPD retries are not a per-connection field; strongSwan's global retransmission settings apply.
Check status under VPN > IPsec > Status Overview.`;

    const switched = c.eff.switched
      ? "\n\nRoute-based cannot narrow selectors here, so this side is generated as policy-based with one child per subnet pair."
      : "";

    return `OPNsense, side ${c.k}: VPN > IPsec > Connections
(the Connections model; field names from docs.opnsense.org)

${psk}${vti}${connection}${routing}${firewall}${switched}`;
  }

  function pfsense(c, kids) {
    const S = c.S;
    const route = c.eff.mode === "route";
    const phase2 = kids.map(([l, r], i) => `Phase 2 #${i + 1}
  Mode ................... ${route ? "Routed (VTI)" : "Tunnel IPv4"}
  Local network .......... ${l.text}
  Remote network ......... ${r.text}
  Encryption ............. ${PF.enc[S.p2enc]}
  Hash ................... ${isGcm(S.p2enc) ? "(none, GCM)" : PF.int[S.p2int]}
  PFS key group .......... ${PF.pfs(S.pfs)}
  Lifetime ............... ${S.p2life}`).join("\n\n");

    return `pfSense, side ${c.k}: VPN > IPsec > Tunnels (Phase 1 / Phase 2)

Phase 1
  Key Exchange version ... IKEv2
  Remote gateway ......... ${c.peer.ip}
  Authentication ......... Mutual PSK
  Pre-Shared Key ......... ${TM.PSK}
  Encryption ............. ${PF.enc[S.p1enc]}
  Hash ................... ${PF.int[S.p1int]}${isGcm(S.p1enc) ? " (PRF)" : ""}
  DH key group ........... ${PF.dh(S.dh)}
  Lifetime ............... ${S.p1life}
  Dead Peer Detection .... delay ${S.dpdInt} s, max failures ${S.dpdRetry}

${phase2}`;
  }

  function checks({ S, k, add }) {
    const p1 = ike(S), p2 = esp(S);
    if (!opnValid(1, p1))
      add("err", `OPNsense (side ${k}): the IKE proposal ${p1} is not in the Connections proposal list, so it cannot be selected. pfSense Tunnels may still accept the separate values.`, "crypto");
    if (!opnValid(2, p2))
      add("err", `OPNsense (side ${k}): the ESP proposal ${p2} is not in the Connections proposal list, so it cannot be selected. Without PFS, only aes256gcm16, aes256-sha1 and aes256-sha256 exist.${S.pfs ? "" : " Turn on PFS (group 14 or higher)."}`, "crypto");
  }

  function generate(c) {
    const any = { text: "0.0.0.0/0" };
    const kids = c.anyAny ? [[any, any]] : c.pairs;
    return [
      { title: "OPNsense (Connections)", text: opnsense(c, kids) },
      { title: "pfSense (Tunnels)", text: pfsense(c, kids) },
    ];
  }

  TM.register({
    id: "opnsense",
    order: 9,
    label: "OPNsense / pfSense",
    short: "OPNsense/pfSense",
    modes: ["policy", "route"],
    narrow: false,
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: ALL.dh,
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0].concat(ALL.dh),
    },
    defaults: { tun: "10" },
    fields: { tun: "VTI reqid" },
    /* GUI labels as pfSense shows them; OPNsense takes the proposal strings in its own output. */
    names: (S) => ({
      p1enc: spell(PF.enc, S.p1enc),
      p1int: spell(PF.int, S.p1int),
      dh: spell(PF.dh, S.dh),
      p2enc: spell(PF.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM, none)" : spell(PF.int, S.p2int),
      pfs: PF.pfs(S.pfs),
      dpd: `DPD delay ${S.dpdInt} (pfSense: max failures ${S.dpdRetry})`,
    }),
    checks,
    generate,
    proposals: { ike, esp, valid: opnValid },
    sources: {
      status: "Syntax reference",
      used: "OPNsense Connections model: pre-shared keys, connection general settings, local/remote authentication, children, virtual tunnel interfaces, gateways and routes. Proposal strings and the set of selectable combinations come from IPsecProposalField in opnsense/core (checked 2026-10-20): no 3DES, MD5 or group 24, and without PFS only aes256gcm16, aes256-sha1 and aes256-sha256. pfSense output keeps the Tunnels (phase 1/phase 2) layout.",
      links: [
        ["OPNsense core: IPsecProposalField (proposal list)", "https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/IPsec/FieldTypes/IPsecProposalField.php"],
        ["OPNsense: IPsec route-based (VTI) PSK setup (Connections)", "https://docs.opnsense.org/manual/how-tos/ipsec-s2s-conn-route.html"],
        ["OPNsense: Virtual Private Networking overview", "https://docs.opnsense.org/manual/vpnet.html"],
      ],
    },
  });
})();
