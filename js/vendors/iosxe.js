/*
 * Cisco IOS-XE
 * Syntax: Cisco IKEv2 and FlexVPN site-to-site configuration guide.
 * Algorithm lists not yet checked against a version-specific table.
 */
(function () {
  "use strict";
  const { isGcm, spell, netStr, maskStr, wildcard, ALL } = TM;

  const N = {
    enc: { aes128: "aes-cbc-128", aes192: "aes-cbc-192", aes256: "aes-cbc-256", aes128gcm: "aes-gcm-128", aes256gcm: "aes-gcm-256", "3des": "3des" },
    int: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    esp: { aes128: "esp-aes 128", aes192: "esp-aes 192", aes256: "esp-aes 256", aes128gcm: "esp-gcm 128", aes256gcm: "esp-gcm 256", "3des": "esp-3des" },
    espInt: { sha1: "esp-sha-hmac", sha256: "esp-sha256-hmac", sha384: "esp-sha384-hmac", sha512: "esp-sha512-hmac", md5: "esp-md5-hmac" },
    pfs: (n) => (n ? "group" + n : "(no set pfs)"),
  };

  function generate(c) {
    const S = c.S;
    const g1 = isGcm(S.p1enc), g2 = isGcm(S.p2enc);
    const n = c.name;
    const tun = c.me.tun || "Tunnel10";
    const wan = c.me.iface || "GigabitEthernet1";
    const transform = `${N.esp[S.p2enc]}${g2 ? "" : " " + N.espInt[S.p2int]}`;
    const pfsLine = S.pfs ? ` set pfs ${N.pfs(S.pfs)}\n` : "";

    const common = `! Cisco IOS-XE, side ${c.k}
crypto ikev2 proposal PROP-${n}
 encryption ${N.enc[S.p1enc]}
 ${g1 ? "prf" : "integrity"} ${N.int[S.p1int]}
 group ${S.dh}
!
crypto ikev2 policy POL-${n}
 proposal PROP-${n}
!
crypto ikev2 keyring KR-${n}
 peer ${n}
  address ${c.peer.ip}
  pre-shared-key ${TM.PSK}
!
crypto ikev2 profile PROF-${n}
 match identity remote address ${c.peer.ip} 255.255.255.255
 authentication remote pre-share
 authentication local pre-share
 keyring local KR-${n}
 lifetime ${S.p1life}
 dpd ${S.dpdInt} ${S.dpdInt} on-demand
 ! dpd <interval> <retry-interval>: IOS-XE retries a fixed number of times
!
crypto ipsec transform-set TS-${n} ${transform}
 mode tunnel
!
`;

    if (c.eff.mode === "route") {
      return common + `crypto ipsec profile IPS-${n}
 set transform-set TS-${n}
 set ikev2-profile PROF-${n}
${pfsLine} set security-association lifetime seconds ${S.p2life}
!
interface ${tun}
 description VPN to ${c.peer.name}
 ip unnumbered ${wan}
 tunnel source ${wan}
 tunnel mode ipsec ipv4
 tunnel destination ${c.peer.ip}
 tunnel protection ipsec profile IPS-${n}
!
${c.remote.map((r) => `ip route ${netStr(r)} ${maskStr(r)} ${tun}`).join("\n")}`;
    }

    const acl = c.pairs.map(([l, r]) => ` permit ip ${netStr(l)} ${wildcard(l)} ${netStr(r)} ${wildcard(r)}`).join("\n");
    const out = common + `ip access-list extended VPN-${n}
${acl}
!
crypto map CMAP 10 ipsec-isakmp
 set peer ${c.peer.ip}
 set transform-set TS-${n}
 set ikev2-profile PROF-${n}
${pfsLine} set security-association lifetime seconds ${S.p2life}
 match address VPN-${n}
!
interface ${wan}
 crypto map CMAP
! Exempt the VPN traffic from NAT (deny it in the NAT ACL).`;
    return c.eff.switched
      ? "! A route-based VTI cannot narrow selectors, so this side is generated as a crypto map.\n" + out
      : out;
  }

  function notes({ add }) {
    add("info", "Cisco IOS-XE takes a DPD retry interval in seconds, not a retry count. The generated config uses the DPD interval for both values; the number of attempts is fixed by the platform.");
  }

  TM.register({
    id: "iosxe",
    order: 5,
    label: "Cisco IOS-XE",
    short: "IOS-XE",
    modes: ["route", "policy"],
    narrow: false,
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: ALL.dh,
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0].concat(ALL.dh),
    },
    defaults: { iface: "GigabitEthernet1", tun: "Tunnel10" },
    fields: { iface: "WAN interface", tun: "Tunnel interface" },
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: "group " + S.dh,
      p2enc: spell(N.esp, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM, none)" : spell(N.espInt, S.p2int),
      pfs: N.pfs(S.pfs),
      dpd: `dpd ${S.dpdInt} ${S.dpdInt} on-demand`,
    }),
    notes,
    generate,
    sources: {
      status: "Syntax reference",
      used: "IKEv2 proposal, policy, keyring and profile; transform sets; IPsec profile with tunnel protection; crypto maps.",
      links: [
        ["Cisco: Configuring IKEv2 and FlexVPN Site-to-Site", "https://www.cisco.com/en/US/docs/ios-xml/ios/sec_conn_ike2vpn/configuration/15-2mt/sec-cfg-ikev2-flex.html"],
      ],
    },
  });
})();
