/*
 * Cisco ASA
 * Syntax: Cisco ASA IKEv2 site-to-site example and ASA command reference (isakmp keepalive).
 * Algorithm lists not yet checked against a version-specific table.
 */
(function () {
  "use strict";
  const { isGcm, spell, netStr, maskStr, ALL } = TM;

  const N = {
    enc: { aes128: "aes", aes192: "aes-192", aes256: "aes-256", aes128gcm: "aes-gcm", aes256gcm: "aes-gcm-256", "3des": "3des" },
    int: { sha1: "sha", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    espInt: { sha1: "sha-1", sha256: "sha-256", sha384: "sha-384", sha512: "sha-512", md5: "md5" },
    pfs: (n) => (n ? "group" + n : "(no set pfs)"),
  };

  function generate(c) {
    const S = c.S;
    const g1 = isGcm(S.p1enc), g2 = isGcm(S.p2enc);
    const n = c.name;
    const outside = c.me.iface || "outside";
    const map = outside.toUpperCase() + "_MAP";
    const setProposal = `set ikev2 ipsec-proposal PROP-${n}`;

    let o = `! Cisco ASA, site ${c.k}
object-group network LOCAL-${n}
${c.local.map((l) => ` network-object ${netStr(l)} ${maskStr(l)}`).join("\n")}
object-group network REMOTE-${n}
${c.remote.map((r) => ` network-object ${netStr(r)} ${maskStr(r)}`).join("\n")}
!
crypto ikev2 policy 10
 encryption ${N.enc[S.p1enc]}
 integrity ${g1 ? "null" : N.int[S.p1int]}
 group ${S.dh}
 prf ${N.int[S.p1int]}
 lifetime seconds ${S.p1life}
! Priority 10 is an example: with several peers, give each different policy its own number.
crypto ikev2 enable ${outside}
!
crypto ipsec ikev2 ipsec-proposal PROP-${n}
 protocol esp encryption ${N.enc[S.p2enc]}
 protocol esp integrity ${g2 ? "null" : N.espInt[S.p2int]}
!
tunnel-group ${c.peer.ip} type ipsec-l2l
tunnel-group ${c.peer.ip} ipsec-attributes
 ikev2 remote-authentication pre-shared-key ${TM.PSK}
 ikev2 local-authentication pre-shared-key ${TM.PSK}
 isakmp keepalive threshold ${S.dpdInt} retry ${S.dpdInt}
 ! threshold = idle seconds before DPD, retry = seconds between attempts
!
`;

    if (c.eff.mode === "route") {
      const tun = c.me.tun || "Tunnel10";
      const nameif = "vti-" + n.toLowerCase();
      o += `crypto ipsec profile IPS-${n}
 ${setProposal}
${S.pfs ? ` set pfs ${N.pfs(S.pfs)}\n` : ""} set security-association lifetime seconds ${S.p2life}
!
interface ${tun}
 nameif ${nameif}
 ip address 169.254.10.1 255.255.255.252
 tunnel source interface ${outside}
 tunnel destination ${c.peer.ip}
 tunnel mode ipsec ipv4
 tunnel protection ipsec profile IPS-${n}
!
${c.remote.map((r) => `route ${nameif} ${netStr(r)} ${maskStr(r)} 169.254.10.2`).join("\n")}
! Replace 169.254.10.x with the agreed tunnel addresses.`;
      return o;
    }

    o += `access-list VPN-${n} extended permit ip object-group LOCAL-${n} object-group REMOTE-${n}
!
crypto map ${map} 10 match address VPN-${n}
crypto map ${map} 10 set peer ${c.peer.ip}
crypto map ${map} 10 ${setProposal}
${S.pfs ? `crypto map ${map} 10 set pfs ${N.pfs(S.pfs)}\n` : ""}crypto map ${map} 10 set security-association lifetime seconds ${S.p2life}
crypto map ${map} interface ${outside}
! Sequence 10 is an example: every peer needs its own sequence number in ${map}.
!
nat (inside,${outside}) source static LOCAL-${n} LOCAL-${n} destination static REMOTE-${n} REMOTE-${n} no-proxy-arp route-lookup`;
    return c.eff.switched ? "! A VTI cannot narrow selectors, so this side is generated as a crypto map.\n" + o : o;
  }

  function notes({ add }) {
    add("info", "Cisco ASA takes a DPD retry interval in seconds, not a retry count. The generated config uses the DPD interval for both values; the number of attempts is fixed by the platform.");
  }

  TM.register({
    id: "asa",
    order: 6,
    label: "Cisco ASA",
    short: "ASA",
    modes: ["policy", "route"],
    narrow: false,
    multiSaNote: true, // one phase 2 SA per subnet pair with crypto maps
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: [2, 5, 14, 15, 19, 20, 21, 24],
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0, 2, 5, 14, 15, 19, 20, 21, 24],
    },
    verify: { dh: [2, 5, 24], pfs: [2, 5, 24] },
    verifyNote: "Newer ASA releases have removed DH 2, 5 and 24.",
    defaults: { iface: "outside", tun: "Tunnel10" },
    fields: { iface: "Outside interface (nameif)", tun: "Tunnel interface" },
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: "group " + S.dh,
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "null" : spell(N.espInt, S.p2int),
      pfs: N.pfs(S.pfs),
      dpd: `keepalive threshold ${S.dpdInt} retry ${S.dpdInt}`,
    }),
    notes,
    generate,
    sources: {
      status: "Syntax reference",
      used: "IKEv2 policy and IPsec proposal, tunnel-group attributes, crypto maps, VTI, isakmp keepalive.",
      links: [
        ["Cisco: ASA IKEv2 site-to-site tunnel configuration example", "https://www.cisco.com/c/en/us/support/docs/security/asa-5500-x-series-next-generation-firewalls/113486-ikev2-s2s-tunnel-00.html"],
        ["Cisco: ASA command reference (isakmp keepalive)", "https://www3-realm.cisco.com/en/US/docs/security/asa/command-reference/i5.html"],
      ],
    },
  });
})();
