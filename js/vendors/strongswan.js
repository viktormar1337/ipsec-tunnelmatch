/*
 * strongSwan (swanctl.conf)
 * Syntax: strongSwan swanctl.conf documentation (latest).
 * Also provides the proposal spelling OPNsense uses (see opnsense.js).
 */
(function () {
  "use strict";
  const { isGcm, spell, ALL } = TM;

  const N = {
    enc: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm: "aes128gcm16", aes256gcm: "aes256gcm16", "3des": "3des" },
    int: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    dh: { 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 19: "ecp256", 20: "ecp384", 21: "ecp521", 24: "modp2048s256" },
  };

  /* IKE and ESP proposal strings, e.g. aes256-sha256-modp2048 and aes256gcm16-modp2048. */
  const ikeProposal = (S) =>
    `${N.enc[S.p1enc]}-${isGcm(S.p1enc) ? "prf" : ""}${N.int[S.p1int]}-${N.dh[S.dh]}`;
  const espProposal = (S) =>
    `${N.enc[S.p2enc]}${isGcm(S.p2enc) ? "" : "-" + N.int[S.p2int]}${S.pfs ? "-" + N.dh[S.pfs] : ""}`;

  function generate(c) {
    const S = c.S;
    const conn = c.name.toLowerCase();
    const route = c.eff.mode === "route";
    const ifid = c.me.tun || "10";
    const selectors = c.anyAny ? [["0.0.0.0/0", "0.0.0.0/0"]] : c.pairs.map(([l, r]) => [l.text, r.text]);

    const children = selectors.map(([l, r], i) => `      ${conn}-${i + 1} {
        local_ts = ${l}
        remote_ts = ${r}
        esp_proposals = ${espProposal(S)}
        rekey_time = ${S.p2life}s${S.p2kb ? `\n        rekey_bytes = ${S.p2kb * 1024}` : ""}
        start_action = trap|start
        dpd_action = restart${route ? `\n        if_id_in = ${ifid}\n        if_id_out = ${ifid}` : ""}
      }`).join("\n");

    const xfrm = route
      ? `
# Route-based (XFRM interface):
#   ip link add xfrm${ifid} type xfrm dev <wan> if_id ${ifid} && ip link set xfrm${ifid} up
${c.remote.map((r) => `#   ip route add ${r.text} dev xfrm${ifid}`).join("\n")}`
      : "";

    return `# /etc/swanctl/conf.d/${conn}.conf, side ${c.k}
connections {
  ${conn} {
    version = 2
    local_addrs = ${c.me.ip}
    remote_addrs = ${c.peer.ip}
    proposals = ${ikeProposal(S)}
    rekey_time = ${S.p1life}s
    dpd_delay = ${S.dpdInt}s
    local {
      auth = psk
      id = ${c.me.ip}
    }
    remote {
      auth = psk
      id = ${c.peer.ip}
    }
    children {
${children}
    }
  }
}
secrets {
  ike-${conn} {
    id-1 = ${c.me.ip}
    id-2 = ${c.peer.ip}
    secret = "${TM.PSK}"
  }
}
# DPD retries: /etc/strongswan.d/charon.conf -> charon { retransmit_tries = ${S.dpdRetry} }${xfrm}
# One child per subnet pair gives one SA per pair, which policy-based peers expect.`;
  }

  function notes({ add }) {
    add("info", "strongSwan: retries come from the global charon.retransmit_tries setting, shown as a comment in the output.");
  }

  TM.register({
    id: "strongswan",
    order: 8,
    label: "strongSwan (swanctl)",
    short: "strongSwan",
    modes: ["route", "policy"],
    narrow: true, // local_ts / remote_ts per child
    supports: {
      p1enc: ALL.enc,
      p1int: ALL.int,
      dh: ALL.dh,
      p2enc: ALL.enc,
      p2int: ALL.int,
      pfs: [0].concat(ALL.dh),
    },
    defaults: { tun: "10" },
    fields: { tun: "XFRM if_id" },
    proposals: { ike: ikeProposal, esp: espProposal },
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: spell(N.dh, S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM, none)" : spell(N.int, S.p2int),
      pfs: S.pfs ? spell(N.dh, S.pfs) : "(none)",
      dpd: `dpd_delay ${S.dpdInt}s, retransmit_tries ${S.dpdRetry}`,
    }),
    notes,
    generate,
    sources: {
      status: "Syntax reference",
      used: "swanctl.conf keys: proposals, esp_proposals, local_ts/remote_ts, rekey_time/rekey_bytes, dpd_delay, dpd_action, start_action, if_id_in/if_id_out.",
      links: [
        ["strongSwan: swanctl.conf (latest)", "https://docs.strongswan.org/docs/latest/swanctl/swanctlConf.html"],
      ],
    },
  });
})();
