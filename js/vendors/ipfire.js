/*
 * IPFire 2.x (strongSwan underneath)
 * Rules: vpnmain.cgi in ipfire-2.x (stored fields and how ike=/esp= are written; lifetimes in
 * hours) and the 2025-02 patches that set the current defaults, checked 2026-10-20.
 *
 * The on-screen labels of the algorithm lists were not available, so the output gives the
 * setting next to the value IPFire stores (for example aes256gcm128). IPFire offers no MD5 and
 * no group 24 in these lists.
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    enc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm: "aes128gcm128", aes256gcm: "aes256gcm128", "3des": "3des" },
    encLabel: { aes128: "AES-128", aes192: "AES-192", aes256: "AES-256", aes128gcm: "AES-128-GCM (128 bit ICV)", aes256gcm: "AES-256-GCM (128 bit ICV)", "3des": "3DES" },
    int: { sha1: "sha1", sha256: "sha2_256", sha384: "sha2_384", sha512: "sha2_512" },
    intLabel: { sha1: "SHA1", sha256: "SHA2 256", sha384: "SHA2 384", sha512: "SHA2 512" },
    dh: { 2: "1024", 5: "1536", 14: "2048", 15: "3072", 19: "e256", 20: "e384", 21: "e521" },
  };
  const hours = (s) => s / 3600;

  function generate(c) {
    const S = c.S;
    const f = (k, v) => `  ${k.padEnd(30, ".")} ${v}`;
    const sel = (label, value) => `${label}   [${value}]`;
    const pairs = c.anyAny ? null : c.pairs;
    const blocks = (pairs || [[{ text: "0.0.0.0/0" }, { text: "0.0.0.0/0" }]]).map(([l, r], i) => [
      `${i + 1}. VPN > IPsec > Add > Net-to-Net Virtual Private Network`,
      f("Name", `${c.name.toLowerCase()}${pairs && pairs.length > 1 ? i + 1 : ""}`),
      f("Enabled", "on"),
      f("Local subnet", l.text),
      f("Remote host/IP", c.peer.ip),
      f("Remote subnet", r.text),
      f("Local ID / Remote ID", "leave empty (the WAN addresses are used)"),
      f("IKE version", "IKEv2"),
      f("Use a pre-shared key", TM.PSK),
      "  Advanced settings (leave only the selection below ticked)",
      f("IKE encryption", sel(spell(N.encLabel, S.p1enc), N.enc[S.p1enc])),
      f("IKE integrity", sel(spell(N.intLabel, S.p1int), N.int[S.p1int])),
      f("IKE grouptype", sel(`group ${S.dh}`, N.dh[S.dh])),
      f("IKE lifetime (hours)", hours(S.p1life)),
      f("ESP encryption", sel(spell(N.encLabel, S.p2enc), N.enc[S.p2enc])),
      f("ESP integrity", isGcm(S.p2enc) ? "(not used with GCM; keep one ticked)" : sel(spell(N.intLabel, S.p2int), N.int[S.p2int])),
      f("ESP grouptype", S.pfs ? sel(`group ${S.pfs}`, N.dh[S.pfs]) : "(PFS off)"),
      f("ESP keylife (hours)", hours(S.p2life)),
      f("Perfect Forward Secrecy", S.pfs ? "on" : "off"),
      f("Dead Peer Detection", `action restart, delay ${S.dpdInt} s, timeout ${S.dpdInt * (S.dpdRetry + 1)} s`),
      f("Only propose settings above", "on"),
    ].join("\n"));
    return [
      `IPFire, side ${c.k}`,
      "",
      ...blocks.flatMap((b) => [b, ""]),
      "Firewall: check that IKE (UDP 500, 4500) and ESP from the peer reach RED, and allow",
      "the remote subnets in Firewall > Firewall Rules if you restrict IPsec traffic.",
    ].join("\n");
  }

  function checks({ S, k, add }) {
    if (S.p1life % 3600 || S.p2life % 3600)
      add("err", `IPFire (side ${k}): IKE lifetime and ESP keylife are set in whole hours; use multiples of 3600 s.`);
  }

  TM.register({
    id: "ipfire",
    order: 14,
    label: "IPFire",
    short: "IPFire",
    modes: ["policy"],
    narrow: false,
    multiSaNote: true,
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p1int: ["sha1", "sha256", "sha384", "sha512"],
      dh: [2, 5, 14, 15, 19, 20, 21],
      p2enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p2int: ["sha1", "sha256", "sha384", "sha512"],
      pfs: [0, 2, 5, 14, 15, 19, 20, 21],
    },
    defaults: {},
    fields: {},
    hint: "One Net-to-Net connection per subnet pair. Lifetimes are whole hours.",
    names: (S) => ({
      p1enc: `${spell(N.encLabel, S.p1enc)} [${spell(N.enc, S.p1enc)}]`,
      p1int: `${spell(N.intLabel, S.p1int)} [${spell(N.int, S.p1int)}]`,
      dh: `[${spell(N.dh, S.dh)}]`,
      p2enc: `${spell(N.encLabel, S.p2enc)} [${spell(N.enc, S.p2enc)}]`,
      p2int: isGcm(S.p2enc) ? "(GCM)" : `${spell(N.intLabel, S.p2int)} [${spell(N.int, S.p2int)}]`,
      pfs: S.pfs ? `on [${spell(N.dh, S.pfs)}]` : "off",
      dpd: `delay ${S.dpdInt} s, timeout ${S.dpdInt * (S.dpdRetry + 1)} s`,
    }),
    checks,
    generate,
    sources: {
      status: "Syntax reference",
      used: "Stored connection fields and how vpnmain.cgi writes ike=/esp= (lifetimes in hours, PFS, 'only propose' flag), algorithm value names and the 2025 defaults. GUI labels of the algorithm lists are approximations; the value in brackets is what IPFire stores.",
      links: [
        ["IPFire: vpnmain.cgi (source)", "https://git.ipfire.org/?p=ipfire-2.x.git;a=blob_plain;f=html/cgi-bin/vpnmain.cgi;hb=HEAD"],
        ["IPFire development list: IPsec default algorithms (2025-02)", "https://lists.ipfire.org/development/20250203205012.3773819-1-michael.tremer@ipfire.org/T"],
      ],
    },
  });
})();
