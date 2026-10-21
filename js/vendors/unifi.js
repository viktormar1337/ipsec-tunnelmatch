/*
 * Ubiquiti UniFi gateways (UniFi Network 8.x / 9.x: UDM, UDR, UXG, UCG, USG)
 * Rules: UniFi help "Site-to-Site IPsec VPN" (Settings > VPN > Site-to-Site VPN > Manual IPsec)
 * and the UMR IPsec article, checked 2026-10-21.
 *
 * Documented: route-based (VTI, default) or policy-based; IKEv1/IKEv2; PSK; local/remote ID;
 * separate IKE and ESP encryption, hash, DH group and lifetime; PFS on/off; defaults
 * AES-128/SHA1, IKE 28800 s, ESP 3600 s. Ubiquiti does not publish the complete dropdown
 * lists, so supports{} is limited to values seen in the help articles and setup guides
 * (AES-128/192/256, 3DES, SHA1/SHA256/SHA384/SHA512, MD5, groups 2/5/14/15/19/20/21).
 * GCM and group 24 are left out until someone confirms them on a gateway.
 */
(function () {
  "use strict";
  const { spell } = TM;

  const N = {
    enc: { aes128: "AES-128", aes192: "AES-192", aes256: "AES-256", "3des": "3DES" },
    hash: { sha1: "SHA1", sha256: "SHA256", sha384: "SHA384", sha512: "SHA512", md5: "MD5" },
  };
  const ALGS = { enc: ["aes128", "aes192", "aes256", "3des"], int: ["sha1", "sha256", "sha384", "sha512", "md5"], dh: [2, 5, 14, 15, 19, 20, 21] };

  function generate(c) {
    const S = c.S;
    const route = c.eff.mode === "route";
    const f = (k, v) => `  ${k.padEnd(28, ".")} ${v}`;
    return [
      `UniFi Network, side ${c.k}`,
      "",
      "Settings > VPN > Site-to-Site VPN > Create New > Manual IPsec",
      f("Name", c.name),
      f("Pre-shared key", TM.PSK),
      f("Local IP / WAN", c.me.ip),
      f("Remote IP / Host", c.peer.ip),
      f("VPN type", route ? "Route-based" : "Policy-based"),
      route
        ? f("Remote networks", c.remote.map((r) => r.text).join(", ") + "   (static routes via the VTI)")
        : f("Local networks", c.local.map((l) => l.text).join(", ")),
      ...(route ? [] : [f("Remote networks", c.remote.map((r) => r.text).join(", "))]),
      ...(route ? [f("Tunnel IP", "agree a /30 with the peer (optional on UniFi)")] : []),
      "  Advanced: Manual",
      f("Key exchange version", "IKEv2"),
      f("IKE encryption", spell(N.enc, S.p1enc)),
      f("IKE hash", spell(N.hash, S.p1int)),
      f("IKE DH group", S.dh),
      f("IKE lifetime", S.p1life),
      f("ESP encryption", spell(N.enc, S.p2enc)),
      f("ESP hash", spell(N.hash, S.p2int)),
      f("ESP DH group", S.pfs || S.dh),
      f("ESP lifetime", S.p2life),
      f("Perfect Forward Secrecy", S.pfs ? "on" : "off"),
      f("Local ID / Remote ID", `${c.me.ip} / ${c.peer.ip}`),
      f("MTU", "Auto"),
      "",
      "UniFi creates the firewall rules for the tunnel itself. If the gateway sits behind NAT,",
      "forward UDP 500 and 4500 to it and set Local ID to its public address.",
    ].join("\n");
  }

  function notes({ add }) {
    add("info", "UniFi: DPD timers are not exposed in the Manual IPsec settings; the gateway uses its own defaults.");
  }

  TM.register({
    id: "unifi",
    order: 16,
    label: "Ubiquiti UniFi gateway",
    short: "UniFi",
    modes: ["route", "policy"],
    narrow: false,
    multiSaNote: true,
    supports: {
      p1enc: ALGS.enc,
      p1int: ALGS.int,
      dh: ALGS.dh,
      p2enc: ALGS.enc,
      p2int: ALGS.int,
      pfs: [0].concat(ALGS.dh),
    },
    defaults: {},
    fields: {},
    hint: "Manual IPsec. DPD timers are fixed by UniFi.",
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.hash, S.p1int),
      dh: String(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: spell(N.hash, S.p2int),
      pfs: S.pfs ? `on, DH ${S.pfs}` : "off",
      dpd: "UniFi default (not configurable)",
    }),
    notes,
    generate,
    sources: {
      status: "Syntax reference",
      used: "Manual IPsec fields (route/policy-based, IKE version, separate IKE/ESP encryption, hash, DH group and lifetime, PFS, local/remote ID) and defaults from UniFi help. Ubiquiti doesn't publish the full dropdown lists, so the supported values are a conservative set; please report what your gateway offers.",
      links: [
        ["UniFi help: Site-to-Site IPsec VPN", "https://help.ui.com/hc/en-us/articles/7983431932439"],
        ["UniFi help: IPSec Site-to-Site VPN for UMR", "https://help.ui.com/hc/en-us/articles/31176030265111-IPSec-Site-to-Site-VPN-for-UMR"],
        ["LazyAdmin: UniFi site-to-site VPN (Network 9.3)", "https://lazyadmin.nl/home-network/unifi-site-to-site-vpn/"],
      ],
    },
  });
})();
