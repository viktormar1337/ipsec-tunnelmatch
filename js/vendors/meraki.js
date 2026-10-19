/*
 * Cisco Meraki MX
 * Rules: Meraki IPsec VPN Configuration Settings and Insecure Cipher Deprecation (verified 2026-10-19).
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    enc: { aes128: "AES 128", aes192: "AES 192", aes256: "AES 256", "3des": "3DES" },
    int: { sha1: "SHA1", sha256: "SHA256", md5: "MD5" },
    dh: (n) => "Group " + n,
    pfs: (n) => (n ? "Group " + n : "Off"),
  };

  function generate(c) {
    const S = c.S;
    return `Meraki Dashboard, side ${c.k}
Security & SD-WAN > Site-to-site VPN > Non-Meraki VPN peers > Add a peer

  Name .................. ${c.peer.name}
  IKE version ........... IKEv2
  Public IP ............. ${c.peer.ip}
  Routing ............... ${c.eff.mode === "route" ? "Static (route-based, requires MX 19.2.7+)" : "Policy-based"}
  Private subnets ....... ${c.remote.map((r) => r.text).join(", ")}
  Preshared secret ...... ${TM.PSK}
  IPsec policies ........ Custom

  Phase 1
    Encryption .......... ${spell(N.enc, S.p1enc)}
    Authentication ...... ${spell(N.int, S.p1int)}
    Diffie-Hellman group  ${N.dh(S.dh)}
    Lifetime (seconds) .. ${S.p1life}

  Phase 2
    Encryption .......... ${spell(N.enc, S.p2enc)}
    Authentication ...... ${isGcm(S.p2enc) ? "(GCM not supported)" : spell(N.int, S.p2int)}
    PFS group ........... ${N.pfs(S.pfs)}
    Lifetime (seconds) .. ${S.p2life}

  DPD ................... fixed by the platform (not configurable)

Local networks to send through the tunnel (set "In VPN" = Yes under Local networks):
  ${c.local.map((l) => l.text).join("\n  ")}

Select a single algorithm per field in the custom policy so the proposal is unambiguous.`;
  }

  function checks({ S, k, A, B, add }) {
    const manySubnets = A.nets.length > 1 || B.nets.length > 1;
    if (manySubnets && S[k].mode === "policy")
      add("warn", `Meraki MX (side ${k}) with IKEv2 sends a single traffic selector holding all local and remote subnets. Peers that expect one selector pair per SA (PAN-OS proxy-IDs, ASA crypto maps and others) will not match it. Summarize to one subnet per side, or use route-based on the MX (MX 19.2.7 or later).`);
  }

  function notes({ add }) {
    add("info", "Meraki MX: DPD interval and retries are fixed by the platform and cannot be set in Dashboard.");
  }

  TM.register({
    id: "meraki",
    order: 4,
    label: "Cisco Meraki MX",
    short: "Meraki MX",
    modes: ["policy", "route"],
    narrow: false,
    multiSaNote: true, // one phase 2 SA per subnet pair in policy mode
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "3des"],
      p1int: ["sha1", "sha256", "md5"],
      dh: [2, 5, 14, 15, 21],
      p2enc: ["aes128", "aes192", "aes256", "3des"],
      p2int: ["sha1", "sha256", "md5"],
      pfs: [0, 2, 5, 14, 15, 21],
    },
    verify: { dh: [15, 21], pfs: [15, 21] },
    verifyNote: "DH groups 15 and 21 require MX 19.2 or later.",
    hint: "Route-based toward third-party peers requires MX 19.2.7 or later.",
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: N.dh(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM not supported)" : spell(N.int, S.p2int),
      pfs: N.pfs(S.pfs),
      dpd: "fixed",
    }),
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-19",
      used: "Custom IPsec policy options (no GCM, no SHA-384, DH 1/2/5/14/15/21), firmware for IKEv2 and DH 15/21, single IKEv2 traffic selector with all subnets, MX 27.1 cipher removals, route-based from MX 19.2.7.",
      links: [
        ["Meraki: IPsec VPN Configuration Settings", "https://documentation.meraki.com/SASE_and_SD-WAN/MX/Design_and_Configure/Configuration_Guides/Site-to-site_VPN/IPsec_VPN_Configuration_Settings"],
        ["Meraki: Insecure Cipher Deprecation", "https://documentation.meraki.com/SASE_and_SD-WAN/MX/Product_Information/Compatibility_and_Firmware/Insecure_Cipher_Deprecation"],
        ["Meraki: Custom IPsec policies with Site-to-site VPN", "https://documentation.meraki.com/MX/Site-to-site_VPN/Custom_IPsec_policies_with_Site-to-site_VPN"],
        ["Cloudflare: Cisco Meraki MX route-based (MX 19.2.7 requirement)", "https://developers.cloudflare.com/cloudflare-wan/configuration/third-party/cisco-meraki-static/"],
      ],
    },
  });
})();
