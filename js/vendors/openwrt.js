/*
 * OpenWrt with strongSwan (package strongswan-full; /etc/init.d/swanctl reads /etc/config/ipsec)
 * Rules: swanctl.init in openwrt/packages (net/strongswan/files, checked 2026-10-20), using
 * the remote / tunnel / crypto_proposal schema that release 21.02 onwards reads.
 *
 * Algorithms are strongSwan names, so everything the tool knows is available. The init script
 * refuses a hash_algorithm on AEAD (GCM) proposals; for IKE with GCM the PRF goes in
 * prf_algorithm instead.
 */
(function () {
  "use strict";
  const { isGcm, spell, ALL } = TM;

  const N = {
    enc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm: "aes128gcm16", aes256gcm: "aes256gcm16", "3des": "3des" },
    hash: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    dh: { 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 19: "ecp256", 20: "ecp384", 21: "ecp521", 24: "modp2048s256" },
  };

  /* What swanctl.init builds from these options. */
  const proposals = {
    ike: (S) => `${N.enc[S.p1enc]}${isGcm(S.p1enc) ? "" : "-" + N.hash[S.p1int]}-prf${N.hash[S.p1int]}-${N.dh[S.dh]}`,
    esp: (S) => `${N.enc[S.p2enc]}${isGcm(S.p2enc) ? "" : "-" + N.hash[S.p2int]}${S.pfs ? "-" + N.dh[S.pfs] : ""}`,
  };

  const uciName = (s) => s.toLowerCase().replace(/[^a-z0-9_]/g, "_");

  function generate(c) {
    const S = c.S;
    const n = uciName(c.name);
    const r = `ipsec.${n}`;
    const pairs = c.anyAny ? [[{ text: "0.0.0.0/0" }, { text: "0.0.0.0/0" }]] : c.pairs;
    const L = [
      `# OpenWrt (strongswan-full), site ${c.k}: run in a shell on the router.`,
      "touch /etc/config/ipsec",
      `uci set ${r}=remote`,
      `uci set ${r}.enabled='1'`,
      `uci set ${r}.gateway='${c.peer.ip}'`,
      `uci set ${r}.local_ip='${c.me.ip}'`,
      `uci set ${r}.authentication_method='psk'`,
      `uci set ${r}.pre_shared_key='${TM.PSK}'`,
      `uci set ${r}.local_identifier='${c.me.ip}'`,
      `uci set ${r}.remote_identifier='${c.peer.ip}'`,
      `uci set ${r}.keyexchange='ikev2'`,
      `uci set ${r}.dpddelay='${S.dpdInt}s'`,
      `uci set ${r}.rekeytime='${S.p1life}s'`,
      `uci set ${r}_ike=crypto_proposal`,
      `uci set ${r}_ike.encryption_algorithm='${N.enc[S.p1enc]}'`,
    ];
    if (!isGcm(S.p1enc)) L.push(`uci set ${r}_ike.hash_algorithm='${N.hash[S.p1int]}'`);
    L.push(
      `uci set ${r}_ike.prf_algorithm='prf${N.hash[S.p1int]}'`,
      `uci set ${r}_ike.dh_group='${N.dh[S.dh]}'`,
      `uci add_list ${r}.crypto_proposal='${n}_ike'`,
      `uci set ${r}_esp=crypto_proposal`,
      `uci set ${r}_esp.encryption_algorithm='${N.enc[S.p2enc]}'`
    );
    if (!isGcm(S.p2enc)) L.push(`uci set ${r}_esp.hash_algorithm='${N.hash[S.p2int]}'`);
    if (S.pfs) L.push(`uci set ${r}_esp.dh_group='${N.dh[S.pfs]}'`);
    pairs.forEach(([l, rm], i) => {
      const t = `${r}_t${i + 1}`;
      L.push(
        `uci set ${t}=tunnel`,
        `uci add_list ${t}.local_subnet='${l.text}'`,
        `uci add_list ${t}.remote_subnet='${rm.text}'`,
        `uci set ${t}.startaction='start'`,
        `uci set ${t}.dpdaction='restart'`,
        `uci set ${t}.closeaction='start'`,
        `uci set ${t}.rekeytime='${S.p2life}s'`,
        `uci add_list ${t}.crypto_proposal='${n}_esp'`,
        `uci add_list ${r}.tunnel='${n}_t${i + 1}'`
      );
    });
    L.push("uci commit ipsec", "# Firewall: IKE, NAT-T and ESP from the peer, tunnel traffic in, and no masquerade for it");
    const rule = (name, opts) => [`uci add firewall rule`, `uci set firewall.@rule[-1].name='${name}'`,
      ...Object.entries(opts).map(([k, v]) => `uci set firewall.@rule[-1].${k}='${v}'`)];
    L.push(
      ...rule(`Allow-IKE-${n}`, { src: "wan", src_ip: c.peer.ip, proto: "udp", dest_port: "500 4500", target: "ACCEPT" }),
      ...rule(`Allow-ESP-${n}`, { src: "wan", src_ip: c.peer.ip, proto: "esp", target: "ACCEPT" })
    );
    c.remote.forEach((rm, i) => L.push(
      ...rule(`Allow-IPsec-in-${n}-${i + 1}`, { src: "wan", src_ip: rm.text, dest: "lan", proto: "all", target: "ACCEPT" }),
      ...rule(`Allow-IPsec-host-${n}-${i + 1}`, { src: "wan", src_ip: rm.text, proto: "all", target: "ACCEPT" })
    ));
    pairs.forEach(([l, rm], i) => L.push(
      "uci add firewall nat",
      `uci set firewall.@nat[-1].name='No-NAT-IPsec-${n}-${i + 1}'`,
      "uci set firewall.@nat[-1].src='wan'",
      `uci set firewall.@nat[-1].src_ip='${l.text}'`,
      `uci set firewall.@nat[-1].dest_ip='${rm.text}'`,
      "uci set firewall.@nat[-1].proto='all'",
      "uci set firewall.@nat[-1].target='ACCEPT'"
    ));
    L.push(
      "uci commit firewall",
      "/etc/init.d/firewall restart",
      "# strongswan-full also installs the legacy ipsec service; only one of them may run charon",
      "[ -x /etc/init.d/ipsec ] && { /etc/init.d/ipsec stop; /etc/init.d/ipsec disable; }",
      "# a charon, or its swanctl --load-all child, left over from both services can hold UDP 500/4500",
      "killall -q -9 charon swanctl",
      "/etc/init.d/swanctl enable",
      "/etc/init.d/swanctl restart",
    );
    return L.join("\n");
  }

  function notes({ add }) {
    add("info", "OpenWrt: needs the strongswan-full package, and kmod-crypto-seqiv for AES-GCM in phase 2, which strongswan-full does not pull in (without it the kernel refuses the ESP SA: \"unable to initialize cryptographic operations\"): apk add strongswan-full kmod-crypto-seqiv on 25.x, opkg install strongswan-full kmod-crypto-seqiv on 24.x. DPD retries follow strongSwan's global retransmission settings.");
  }

  TM.register({
    id: "openwrt",
    order: 12,
    label: "OpenWrt (strongSwan)",
    short: "OpenWrt",
    modes: ["policy"],
    narrow: false,
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: ALL.dh,
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0].concat(ALL.dh),
    },
    defaults: {},
    fields: {},
    hint: "Generated as UCI commands for /etc/config/ipsec (read by /etc/init.d/swanctl) and the firewall. The legacy ipsec service, which strongswan-full also enables, is stopped and disabled: both start charon from the same config, and a charon or swanctl process left over from the two can keep UDP 500/4500, so they are killed before swanctl restarts (this briefly drops any running IPsec tunnels on the router).",
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: isGcm(S.p1enc) ? `prf${spell(N.hash, S.p1int)} (no hash with GCM)` : `${spell(N.hash, S.p1int)}, prf${spell(N.hash, S.p1int)}`,
      dh: spell(N.dh, S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(none, GCM)" : spell(N.hash, S.p2int),
      pfs: S.pfs ? spell(N.dh, S.pfs) : "(no dh_group)",
      dpd: `dpddelay ${S.dpdInt}s`,
    }),
    notes,
    generate,
    proposals,
    sources: {
      status: "Verified 2026-10-20",
      used: "swanctl.init in openwrt/packages: the remote / tunnel / crypto_proposal options (gateway, local_ip, authentication_method, pre_shared_key, identifiers, keyexchange, dpddelay, rekeytime, local_subnet, remote_subnet, startaction, dpdaction), how proposals are built, and that AEAD proposals must not carry a hash_algorithm.",
      links: [
        ["openwrt/packages: strongswan swanctl.init", "https://github.com/openwrt/packages/blob/master/net/strongswan/files/swanctl.init"],
        ["OpenWrt wiki: IPsec with strongSwan", "https://openwrt.org/docs/guide-user/services/vpn/strongswan/start"],
      ],
    },
  });
})();
