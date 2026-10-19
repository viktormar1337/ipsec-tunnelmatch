/*
 * Fortinet FortiGate (FortiOS)
 * Syntax: FortiOS 7.4.2 CLI reference, vpn ipsec phase1-interface / phase2-interface.
 * Algorithm lists not yet checked against a version-specific table.
 */
(function () {
  "use strict";
  const { isGcm, spell, netStr, maskStr, i2s, ALL } = TM;

  const N = {
    enc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm: "aes128gcm", aes256gcm: "aes256gcm", "3des": "3des" },
    int: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
  };

  const phase1Proposal = (S) =>
    isGcm(S.p1enc) ? `${N.enc[S.p1enc]}-prf${N.int[S.p1int]}` : `${N.enc[S.p1enc]}-${N.int[S.p1int]}`;
  const phase2Proposal = (S) =>
    isGcm(S.p2enc) ? N.enc[S.p2enc] : `${N.enc[S.p2enc]}-${N.int[S.p2int]}`;

  function generate(c) {
    const S = c.S;
    const n = c.name.slice(0, 15); // FortiOS phase1 names are limited to 15 characters
    const wan = c.me.iface || "wan1";
    const any = { net: 0, mask: 0 };
    const selectors = c.anyAny ? [[any, any]] : c.pairs;

    const phase2 = selectors.map(([l, r], i) => `    edit "${n}-p2-${i + 1}"
        set phase1name "${n}"
        set proposal ${phase2Proposal(S)}
${S.pfs ? `        set dhgrp ${S.pfs}` : "        set pfs disable"}
        set keylifeseconds ${S.p2life}
${S.p2kb ? `        set keylife-type both\n        set keylifekbs ${S.p2kb}\n` : ""}        set src-subnet ${netStr(l)} ${i2s(l.mask)}
        set dst-subnet ${netStr(r)} ${i2s(r.mask)}
    next`).join("\n");

    const routes = c.remote.map((r) => `    edit 0
        set dst ${netStr(r)} ${maskStr(r)}
        set device "${n}"
    next`).join("\n");

    return `# FortiOS CLI, side ${c.k}
config vpn ipsec phase1-interface
    edit "${n}"
        set interface "${wan}"
        set ike-version 2
        set peertype any
        set net-device disable
        set proposal ${phase1Proposal(S)}
        set dhgrp ${S.dh}
        set keylife ${S.p1life}
        set dpd on-idle
        set dpd-retryinterval ${S.dpdInt}
        set dpd-retrycount ${S.dpdRetry}
        set remote-gw ${c.peer.ip}
        set psksecret ${TM.PSK}
    next
end
config vpn ipsec phase2-interface
${phase2}
end
config router static
${routes}
end
# Add firewall policies lan <-> "${n}" in both directions.`;
  }

  TM.register({
    id: "fortigate",
    order: 3,
    label: "Fortinet FortiGate (FortiOS)",
    short: "FortiGate",
    modes: ["route"],
    narrow: true, // phase 2 selectors
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: [2, 5, 14, 15, 19, 20, 21],
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0, 2, 5, 14, 15, 19, 20, 21],
    },
    defaults: { iface: "wan1" },
    fields: { iface: "WAN interface" },
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: String(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM, none)" : spell(N.int, S.p2int),
      pfs: S.pfs ? String(S.pfs) : "pfs disable",
      dpd: `retryinterval ${S.dpdInt}, retrycount ${S.dpdRetry}`,
    }),
    generate,
    sources: {
      status: "Syntax reference",
      used: "phase1-interface and phase2-interface commands, proposal format, dhgrp, dpd-retrycount and dpd-retryinterval.",
      links: [
        ["FortiOS 7.4.2 CLI reference: vpn ipsec phase1-interface", "https://docs.fortinet.com/document/fortigate/7.4.2/cli-reference/333620"],
      ],
    },
  });
})();
