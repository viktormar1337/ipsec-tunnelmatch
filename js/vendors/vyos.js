/*
 * VyOS 1.4 / 1.5 / rolling
 * Rules: VyOS CLI definitions in vyos/vyos-1x (vpn_ipsec.xml.in and the ipsec includes) and the
 * proposal builder (python/vyos/template.py, _get_esp_ike_cipher), checked 2026-10-20; syntax from
 * the VyOS site-to-site IPsec documentation.
 *
 * VyOS passes strongSwan algorithm names through and always writes proposals as
 * encryption-hash[-prf][-dh]. With AES-GCM the hash is ignored for ESP and becomes the PRF
 * for IKE, but VyOS still requires one, so the output sets it.
 */
(function () {
  "use strict";
  const { isGcm, spell, ALL } = TM;

  const N = {
    enc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm: "aes128gcm128", aes256gcm: "aes256gcm128", "3des": "3des" },
    hash: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
  };

  /* What VyOS hands to strongSwan for these settings (same rule as _get_esp_ike_cipher). */
  const DH = { 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 19: "ecp256", 20: "ecp384", 21: "ecp521", 24: "modp2048s256" };
  const espHash = (S) => (isGcm(S.p2enc) ? "sha256" : N.hash[S.p2int]);
  const proposals = {
    ike: (S) => `${N.enc[S.p1enc]}-${N.hash[S.p1int]}-prf${N.hash[S.p1int]}-${DH[S.dh]}`,
    esp: (S) => `${N.enc[S.p2enc]}-${espHash(S)}${S.pfs ? "-" + DH[S.pfs] : ""}`,
  };

  function generate(c) {
    const S = c.S;
    const n = c.name.toLowerCase();
    const route = c.eff.mode === "route";
    const wan = c.me.iface || "eth0";
    const vti = (c.me.tun || "vti10").trim() || "vti10";
    const ike = `set vpn ipsec ike-group IKE-${c.name}`;
    const esp = `set vpn ipsec esp-group ESP-${c.name}`;
    const peer = `set vpn ipsec site-to-site peer ${n}`;
    const psk = `set vpn ipsec authentication psk PSK-${c.name}`;

    const L = [
      `# VyOS 1.4/1.5 configuration mode, side ${c.k}. configure, paste, commit, save.`,
      `set vpn ipsec interface '${wan}'`,
      `${psk} id '${c.me.ip}'`,
      `${psk} id '${c.peer.ip}'`,
      `${psk} secret '${TM.PSK}'`,
      `${ike} key-exchange 'ikev2'`,
      `${ike} lifetime '${S.p1life}'`,
      `${ike} dead-peer-detection action 'restart'`,
      `${ike} dead-peer-detection interval '${S.dpdInt}'`,
      `${ike} dead-peer-detection timeout '${S.dpdInt * (S.dpdRetry + 1)}'`,
      `${ike} proposal 1 encryption '${N.enc[S.p1enc]}'`,
      `${ike} proposal 1 hash '${N.hash[S.p1int]}'`,
      `${ike} proposal 1 prf 'prf${N.hash[S.p1int]}'`,
      `${ike} proposal 1 dh-group '${S.dh}'`,
      `${esp} lifetime '${S.p2life}'`,
      `${esp} mode 'tunnel'`,
      `${esp} pfs '${S.pfs ? "dh-group" + S.pfs : "disable"}'`,
      `${esp} proposal 1 encryption '${N.enc[S.p2enc]}'`,
      `${esp} proposal 1 hash '${espHash(S)}'${isGcm(S.p2enc) ? "   # required by VyOS, not used with GCM" : ""}`,
      `${peer} authentication mode 'pre-shared-secret'`,
      `${peer} authentication local-id '${c.me.ip}'`,
      `${peer} authentication remote-id '${c.peer.ip}'`,
      `${peer} connection-type 'initiate'`,
      `${peer} ike-group 'IKE-${c.name}'`,
      `${peer} default-esp-group 'ESP-${c.name}'`,
      `${peer} local-address '${c.me.ip}'`,
      `${peer} remote-address '${c.peer.ip}'`,
    ];

    if (route) {
      const num = vti.replace(/\D/g, "") || "10";
      L.push(
        `set interfaces vti ${vti} address '169.254.${num}.1/30'   # agree the tunnel addresses with the peer`,
        `${peer} vti bind '${vti}'`,
        `${peer} vti esp-group 'ESP-${c.name}'`,
        "set vpn ipsec options disable-route-autoinstall",
        ...c.remote.map((r) => `set protocols static route ${r.text} interface ${vti}`)
      );
    } else {
      const pairs = c.anyAny ? [[{ text: "0.0.0.0/0" }, { text: "0.0.0.0/0" }]] : c.pairs;
      pairs.forEach(([l, r], i) => {
        L.push(`${peer} tunnel ${i} local prefix '${l.text}'`, `${peer} tunnel ${i} remote prefix '${r.text}'`);
      });
      L.push("# If there is source NAT on the WAN, exclude the tunnel traffic from it:",
        ...pairs.map(([l, r], i) => `#   set nat source rule ${10 + i} destination address '${r.text}'; set nat source rule ${10 + i} source address '${l.text}'; set nat source rule ${10 + i} exclude`));
    }
    return L.join("\n");
  }

  function notes({ add }) {
    add("info", "VyOS: the DPD timeout is set to interval × (retries + 1); with IKEv2, strongSwan's retransmission settings decide when the peer is declared dead.");
  }

  TM.register({
    id: "vyos",
    order: 11,
    label: "VyOS",
    short: "VyOS",
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
    defaults: { iface: "eth0", tun: "vti10" },
    fields: { iface: "IPsec interface", tun: "VTI interface" },
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: `hash ${spell(N.hash, S.p1int)}, prf prf${spell(N.hash, S.p1int)}`,
      dh: String(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "sha256 (required, unused with GCM)" : spell(N.hash, S.p2int),
      pfs: S.pfs ? "dh-group" + S.pfs : "disable",
      dpd: `interval ${S.dpdInt}, timeout ${S.dpdInt * (S.dpdRetry + 1)}`,
    }),
    notes,
    generate,
    proposals,
    sources: {
      status: "Verified 2026-10-20",
      used: "CLI value lists from vyos-1x (encryption, hash, prf, dh-group 1–35, pfs, lifetimes 30–86400 s, DPD 2–86400 s), the proposal builder that always writes encryption-hash[-prf][-dh], site-to-site peer syntax (authentication, local/remote-id, tunnel prefixes, VTI bind) and the SNAT exclude advice.",
      links: [
        ["VyOS docs: IPsec site-to-site", "https://docs.vyos.io/en/latest/configuration/vpn/ipsec.html"],
        ["vyos-1x: vpn_ipsec.xml.in (CLI definitions)", "https://github.com/vyos/vyos-1x/blob/current/interface-definitions/vpn_ipsec.xml.in"],
        ["vyos-1x: template.py (proposal builder)", "https://github.com/vyos/vyos-1x/blob/current/python/vyos/template.py"],
      ],
    },
  });
})();
