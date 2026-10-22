/*
 * Check Point Quantum Security Gateway, Gaia R82 (R82, R82.10, R82.20 take the same config),
 * managed by a Security Management Server
 * Rules: Site to Site VPN admin guide R82 ("IPsec and IKE" algorithm lists, "Best
 * Practices for Quantum Safe Key Exchange and VPN Tunnel Encryption"), checked 2026-10-22, and
 * the Management API (vpn-community-star, interoperable-device) as documented in the
 * check_point.mgmt Ansible collection 6.9.0.
 *
 * R82: phase 1 AES-128/256, AES-GCM-128/256, 3DES, SHA1/SHA-256/384/512, MD5, AES-XCBC,
 * DH 1/2/5/14/15/16/17/18/19/20/21 (R81.20 had neither GCM in phase 1 nor DH 15/21; R81.x is not covered).
 * Phase 2: AES-128/256, AES-GCM-128/256, 3DES. PFS: the guide lists 1/2/5/14/19/20; 15 and 21 are flagged.
 * No AES-192 anywhere. Group 24 is not in the admin guides.
 * The peer is an Interoperable Device with a manual encryption domain; the tunnel is a star
 * community with a custom encryption suite. Route-based uses a numbered VTI in Gaia clish and
 * an empty encryption domain. IKE DPD for third-party peers is not in the API.
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    p1enc: { aes128: "aes-128", aes256: "aes-256", aes128gcm: "aes-gcm-128", aes256gcm: "aes-gcm-256", "3des": "3des" },
    p2enc: { aes128: "aes-128", aes256: "aes-256", aes128gcm: "aes-gcm-128", aes256gcm: "aes-gcm-256", "3des": "3des" },
    int: { sha1: "sha1", sha256: "sha256", sha384: "sha384", sha512: "sha512", md5: "md5" },
    dh: (n) => "group-" + n,
  };

  function generate(c) {
    const S = c.S;
    const route = c.eff.mode === "route";
    const gw = (c.me.iface || "").trim() || "<gateway-object>";
    const vti = (String(c.me.tun || "10").match(/\d+/) || ["10"])[0];
    const peer = `tm-${c.name.toLowerCase()}`;
    const comm = `TM-${c.name}`;
    const grp = `${peer}-encdom`;
    const m = (cmd) => `mgmt_cli ${cmd} -s id.txt`;
    const netName = (r) => `${peer}-net-${r.text.replace(/[./]/g, "_")}`;

    const L = [
      `# Check Point, site ${c.k}. Run on the Security Management Server (expert mode).`,
      "mgmt_cli login -r true > id.txt",
      "",
      "# Peer encryption domain",
    ];
    if (route) {
      L.push(m(`add group name "${grp}" comments "empty: route-based (VTI)"`));
    } else {
      c.remote.forEach((r) => {
        const [ip, len] = r.text.split("/");
        L.push(m(`add network name "${netName(r)}" subnet "${ip}" mask-length ${len}`));
      });
      L.push(m(`add group name "${grp}" ${c.remote.map((r, i) => `members.${i + 1} "${netName(r)}"`).join(" ")}`));
    }
    L.push(
      "",
      "# The peer as an Interoperable Device",
      m(`add interoperable-device name "${peer}" ip-address "${c.peer.ip}" vpn-settings.vpn-domain-type "manual" vpn-settings.vpn-domain "${grp}"`),
      "",
      "# Star community with a custom encryption suite (the key is entered here, keep it out of shell history)",
      ...(isGcm(S.p1enc) || [15, 21].includes(S.dh)
        ? ["# If mgmt_cli rejects the phase 1 AES-GCM or DH 15/21 value, set it in SmartConsole",
           "# instead (community > Encryption > Custom encryption suite)."]
        : []),
      m([
        `add vpn-community-star name "${comm}"`,
        `center-gateways.1 "${gw}" satellite-gateways.1 "${peer}"`,
        `encryption-method "ikev2 only" encryption-suite "custom"`,
        `ike-phase-1.encryption-algorithm "${N.p1enc[S.p1enc]}" ike-phase-1.data-integrity "${N.int[S.p1int]}"`,
        `ike-phase-1.diffie-hellman-group "${N.dh(S.dh)}"`,
        `ike-phase-1.ike-p1-rekey-time ${Math.round(S.p1life / 60)} ike-phase-1.ike-p1-rekey-time-unit "minutes"`,
        `ike-phase-2.encryption-algorithm "${N.p2enc[S.p2enc]}"` + (isGcm(S.p2enc) ? "" : ` ike-phase-2.data-integrity "${N.int[S.p2int]}"`),
        `ike-phase-2.ike-p2-use-pfs ${S.pfs ? "true" : "false"}` + (S.pfs ? ` ike-phase-2.ike-p2-pfs-dh-grp "${N.dh(S.pfs)}"` : ""),
        `ike-phase-2.ike-p2-rekey-time ${S.p2life} ike-phase-2.ike-p2-rekey-time-unit "seconds"`,
        `tunnel-granularity "${route ? "universal" : "per_subnet"}"`,
        `use-shared-secret true shared-secrets.1.external-gateway "${peer}" shared-secrets.1.shared-secret "${TM.PSK}"`,
      ].join(" \\\n    ")),
      "",
      m("publish"),
      "mgmt_cli logout -s id.txt; rm -f id.txt"
    );

    if (route) {
      L.push(
        "",
        "# On the gateway, Gaia clish: numbered VTI to the peer and routes",
        `add vpn tunnel ${vti} type numbered local 169.254.${vti}.1 remote 169.254.${vti}.2 peer ${peer}`,
        ...c.remote.map((r) => `set static-route ${r.text} nexthop gateway logical vpnt${vti} on`),
        "save config",
        "# Agree the 169.254.x.x tunnel addresses with the peer. Then fetch the topology",
        "# of the gateway in SmartConsole so vpnt" + vti + " shows up."
      );
    } else {
      L.push(
        "",
        `# The gateway's own encryption domain must hold ${c.local.map((l) => l.text).join(", ")}`,
        `# (gateway object > Network Management > VPN Domain).`
      );
    }
    L.push(
      "",
      "# SmartConsole: add an access rule for the traffic with VPN = " + comm + ",",
      "# exclude it from NAT, then install policy on " + gw + "."
    );
    return L.join("\n");
  }

  function checks({ S, k, add }) {
    const id = Number((String(S[k].tun || "10").match(/\d+/) || ["10"])[0]);
    if (S[k].mode === "route" && (id < 1 || id > 99)) add("err", `Check Point (site ${k}): the VTI ID must be 1–99.`);
    if (S.p1life % 60) add("err", `Check Point (site ${k}): the IKE rekey time is set in whole minutes; use a multiple of 60 s.`);
  }

  function notes({ S, add }) {
    add("info", "Check Point: the output is for R82 gateways (R82, R82.10, R82.20 take the same config). Check Point's recommended version is R82.10 with the latest Jumbo Hotfix take.");
    add("info", "Check Point R82 best practice for VPN communities: IKEv2 only, custom suite with AES-GCM-128 or stronger, SHA-384, a DH group stronger than 15, PFS on, and Quantum Safe Key Exchange (ML-KEM from R82 Jumbo Hotfix Take 41) when the peer supports it.");
    if (S.dh < 15 || (S.pfs && S.pfs < 15)) add("info", `Check Point recommends a DH group stronger than 15; group ${S.dh < 15 ? S.dh : S.pfs} is below that.`);
    add("info", "Check Point: DPD toward a third-party peer is not in the management API. For IKEv2, set tunnel_keepalive_method = dpd on the Interoperable Device in GuiDBedit; the interval is fixed by the gateway.");
  }

  TM.register({
    id: "checkpoint",
    order: 17,
    label: "Check Point Quantum (R82)",
    short: "Check Point",
    modes: ["policy", "route"],
    narrow: false,
    multiSaNote: true,
    supports: {
      p1enc: ["aes128", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p1int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      dh: [2, 5, 14, 15, 19, 20, 21],
      p2enc: ["aes128", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p2int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      pfs: [0, 2, 5, 14, 15, 19, 20, 21],
    },
    verify: { pfs: [15, 21] },
    verifyNote: "the R82 admin guide lists PFS groups 1, 2, 5, 14, 19 and 20 only; check that your gateway offers it.",
    defaults: { iface: "gw-site", tun: "10" },
    fields: { iface: "Gateway object name", tun: "VTI ID" },
    hint: "R82 gateways. No AES-192. The IKE rekey time is in minutes.",
    names: (S) => ({
      p1enc: spell(N.p1enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: N.dh(S.dh),
      p2enc: spell(N.p2enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM)" : spell(N.int, S.p2int),
      pfs: S.pfs ? N.dh(S.pfs) : "PFS off",
      dpd: "tunnel_keepalive_method dpd (GuiDBedit)",
    }),
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-22",
      used: "Supported algorithms for R82 and Check Point's R82 best practices from the Site to Site VPN admin guides. Management API values for vpn-community-star (phase 1 and 2 algorithms, DH and PFS groups, rekey times and units, encryption method and suite, tunnel granularity, shared secrets) and interoperable-device (manual VPN domain), from the check_point.mgmt collection 6.9.0. Numbered VTI syntax (tunnel ID 1–99, interface vpnt<ID>) from the Gaia admin guide.",
      links: [
        ["Check Point R82 Site to Site VPN: IPsec and IKE", "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SitetoSiteVPN_AdminGuide/Content/Topics-VPNSG/IPsec-and-IKE.htm"],
        ["Ansible check_point.mgmt: cp_mgmt_vpn_community_star", "https://docs.ansible.com/projects/ansible/latest/collections/check_point/mgmt/cp_mgmt_vpn_community_star_module.html"],
        ["Ansible check_point.mgmt: cp_mgmt_interoperable_device", "https://docs.ansible.com/projects/ansible/latest/collections/check_point/mgmt/cp_mgmt_interoperable_device_module.html"],
        ["Check Point R82 Gaia: VPN Tunnel Interfaces", "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/Topics-GAG/VPN-Tunnel-Interfaces.htm"],
        ["Check Point R82: Best Practices for Quantum Safe Key Exchange and VPN Tunnel Encryption", "https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SitetoSiteVPN_AdminGuide/Content/Topics-VPNSG/Quantum-Safe-Key-Exchange.htm"],
      ],
    },
  });
})();
