/*
 * OPNsense (Connections model) and pfSense (Tunnels model)
 * Syntax: OPNsense docs, IPsec route-based (VTI) PSK setup and VPN overview.
 * OPNsense proposals use strongSwan syntax, so the spelling comes from strongswan.js.
 * Algorithm lists not yet checked against a version-specific table.
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

  const sw = () => TM.vendor("strongswan").proposals;

  function opnsense(c, kids) {
    const S = c.S;
    const route = c.eff.mode === "route";
    const reqid = (c.me.tun || "10").trim() || "10";
    const ike = sw().ike(S), esp = sw().esp(S);
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
     ESP proposals ........... ${esp}
     Start action ............ ${route ? "Trap" : "Start"}
     Rekey time (s) .......... ${S.p2life}   (advanced mode)`).join("\n");

    const connection = `
${step()}. Connection ................ VPN > IPsec > Connections > +
   General settings
     Description ............. ${c.peer.name}
     Version ................. IKEv2
     Proposals ............... ${ike}   (remove the default first)
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
    generate,
    sources: {
      status: "Syntax reference",
      used: "OPNsense Connections model: pre-shared keys, connection general settings, local/remote authentication, children, virtual tunnel interfaces, gateways and routes. Proposals use strongSwan syntax. pfSense output keeps the Tunnels (phase 1/phase 2) layout.",
      links: [
        ["OPNsense: IPsec route-based (VTI) PSK setup (Connections)", "https://docs.opnsense.org/manual/how-tos/ipsec-s2s-conn-route.html"],
        ["OPNsense: Virtual Private Networking overview", "https://docs.opnsense.org/manual/vpnet.html"],
      ],
    },
  });
})();
