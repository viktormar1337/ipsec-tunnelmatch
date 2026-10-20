/*
 * Sophos Firewall (SFOS)
 * Rules: Sophos Firewall help, "IPsec encryption algorithms" (SFOS 21.0) and "Add an IPsec
 * profile" (19.0), checked 2026-10-20.
 *
 * IKEv2 phase 1 offers AES-GCM; the PRF can't be set and is chosen from the authentication
 * algorithm. DH groups 1-21 and 25-31, no group 24. Site-to-site connections are
 * policy-based or route-based (tunnel interface).
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    enc: { aes128: "AES128", aes192: "AES192", aes256: "AES256", aes128gcm: "AES128GCM16", aes256gcm: "AES256GCM16", "3des": "3DES" },
    auth: { sha1: "SHA1", sha256: "SHA2 256", sha384: "SHA2 384", sha512: "SHA2 512", md5: "MD5" },
    dh: { 2: "2 (DH1024)", 5: "5 (DH1536)", 14: "14 (DH2048)", 15: "15 (DH3072)", 19: "19 (ecp256)", 20: "20 (ecp384)", 21: "21 (ecp521)" },
  };

  function generate(c) {
    const S = c.S;
    const route = c.eff.mode === "route";
    const prof = `TM-${c.name}`;
    const pairs = c.anyAny ? null : c.pairs;
    const f = (k, v) => `  ${k.padEnd(28, ".")} ${v}`;

    return [
      `Sophos Firewall, side ${c.k}`,
      "",
      `1. System > Profiles > IPsec profiles > Add: ${prof}`,
      f("Key exchange", "IKEv2"),
      f("Key negotiation tries", "0 (unlimited)"),
      f("Re-key connection", "on"),
      f("SHA2 with 96-bit truncation", "off"),
      "  Phase 1",
      f("Key life (seconds)", S.p1life),
      f("DH group", N.dh[S.dh]),
      f("Encryption", spell(N.enc, S.p1enc)),
      f("Authentication", `${spell(N.auth, S.p1int)}${isGcm(S.p1enc) ? "   (also gives the PRF)" : ""}`),
      "  Phase 2",
      f("PFS group", S.pfs ? N.dh[S.pfs] : "None"),
      f("Key life (seconds)", S.p2life),
      f("Encryption", spell(N.enc, S.p2enc)),
      f("Authentication", isGcm(S.p2enc) ? "(none needed with GCM)" : spell(N.auth, S.p2int)),
      "  Dead peer detection",
      f("Dead peer detection", "on"),
      f("Check peer after every", `${S.dpdInt} seconds`),
      f("When peer unreachable", "Re-initiate"),
      "",
      `2. Site-to-site VPN > IPsec > Add`,
      f("IP version", "IPv4"),
      f("Connection type", route ? "Tunnel interface" : "Site-to-site"),
      f("Gateway type", "Initiate the connection"),
      f("Profile", prof),
      f("Authentication type", "Preshared key"),
      f("Preshared key", TM.PSK),
      f("Listening interface", `the WAN port with ${c.me.ip}`),
      f("Local ID type / ID", `IP address / ${c.me.ip}`),
      f("Remote gateway address", c.peer.ip),
      f("Remote ID type / ID", `IP address / ${c.peer.ip}`),
      ...(route
        ? [f("Local / remote subnet", "Any / Any (route-based)"),
           "  Then: Network > Interfaces: give the xfrm tunnel interface an address,",
           `  and add routes to ${c.remote.map((r) => r.text).join(", ")} via it.`]
        : [f("Local subnet", c.local.map((l) => l.text).join(", ")),
           f("Remote subnet", c.remote.map((r) => r.text).join(", "))]),
      "",
      "3. Rules and policies > Firewall rules: allow LAN <-> VPN for these subnets",
      "   (the wizard can create them). Leave NAT off for the tunnel traffic.",
      ...(pairs && pairs.length > 1 && !route
        ? ["", "Several local and remote subnets give one child SA per pair; check the peer accepts that."]
        : []),
    ].join("\n");
  }

  function notes({ add }) {
    add("info", "Sophos Firewall: DPD retries are not configurable for IKEv2; the PRF follows the authentication algorithm.");
  }

  TM.register({
    id: "sophos",
    order: 13,
    label: "Sophos Firewall (SFOS)",
    short: "Sophos",
    modes: ["policy", "route"],
    narrow: false,
    multiSaNote: true,
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p1int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      dh: [2, 5, 14, 15, 19, 20, 21],
      p2enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p2int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      pfs: [0, 2, 5, 14, 15, 19, 20, 21],
    },
    defaults: {},
    fields: {},
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.auth, S.p1int),
      dh: spell(N.dh, S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(none, GCM)" : spell(N.auth, S.p2int),
      pfs: S.pfs ? spell(N.dh, S.pfs) : "None",
      dpd: `check peer after every ${S.dpdInt} s, Re-initiate`,
    }),
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-20",
      used: "IKEv2 phase 1 and 2 algorithm tables (AES-CBC/GCM, SHA1/SHA2 256/384/512, MD5, DH 1–21 and 25–31, no group 24), automatic PRF selection, IPsec profile fields (key life, DPD, re-key), site-to-site connection fields.",
      links: [
        ["Sophos Firewall: IPsec encryption algorithms (21.0)", "https://docs.sophos.com/nsg/sophos-firewall/21.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Profiles/IPsecProfiles/IPsecEncryptionAlgorithms/index.html"],
        ["Sophos Firewall: Add an IPsec profile", "https://docs.sophos.com/nsg/sophos-firewall/19.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/Profiles/IPsecProfiles/IPsecProfileAdd/index.html"],
      ],
    },
  });
})();
