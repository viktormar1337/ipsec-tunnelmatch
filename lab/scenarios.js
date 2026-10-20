/*
 * Lab scenarios.
 *
 * Every scenario is a tool state (the same shape the web page saves). The lab
 * generates both sides with the tool's strongSwan generator, brings the tunnel
 * up between two network namespaces and checks what was really negotiated.
 *
 *   expect: "pass"  tunnel must come up, traffic must flow, algorithms must match
 *   expect: "fail"  negotiation must fail (proves the lab catches mismatches)
 *   emulate: per-side proposal overrides, used to reproduce how a platform
 *            behaves on the wire (for example PAN-OS picking the IKE PRF itself),
 *            or { vendor } to use that platform's own proposal spelling
 */
"use strict";

const BASE = {
  tunnelName: "LAB",
  author: "lab",
  p1life: 28800, dpdInt: 10, dpdRetry: 3,
  p2life: 3600, p2kb: 0,
  checklist: {},
  A: { name: "Site A", vendor: "strongswan", ip: "203.0.113.10", nets: "10.10.0.0/16\n10.20.30.0/24", mode: "policy", tun: "10" },
  B: { name: "Site B", vendor: "strongswan", ip: "198.51.100.20", nets: "10.50.0.0/16", mode: "policy", tun: "10" },
};

const profile = (p) => JSON.parse(JSON.stringify(Object.assign({}, BASE, p)));

const RECOMMENDED = { p1enc: "aes256gcm", p1int: "sha384", dh: 20, p2enc: "aes256gcm", p2int: "aes256gcm", pfs: 20 };
const MINIMUM = { p1enc: "aes256", p1int: "sha256", dh: 14, p2enc: "aes256", p2int: "sha256", pfs: 14 };

/* Fixed scenarios. The strongest common profile for every vendor pair is added at run time. */
const FIXED = [
  {
    name: "Recommended baseline (AES-256-GCM, SHA-384, group 20)",
    state: profile(RECOMMENDED),
    expect: "pass",
  },
  {
    name: "Baseline minimum, Meraki-compatible (AES-256-CBC, SHA-256, group 14)",
    state: profile(MINIMUM),
    expect: "pass",
  },
  {
    name: "Group 19 with SHA-256 (ECP-256)",
    state: profile({ p1enc: "aes256", p1int: "sha256", dh: 19, p2enc: "aes256gcm", p2int: "aes256gcm", pfs: 19 }),
    expect: "pass",
  },
  {
    name: "OPNsense proposal spelling, recommended (aes256gcm16-sha384-ecp384 / aes256gcm16-ecp384)",
    state: profile(RECOMMENDED),
    // OPNsense only offers entries from its fixed list, written without "prf"
    emulate: { A: { vendor: "opnsense" } },
    vendors: { A: "opnsense", B: "strongswan" },
    expect: "pass",
  },
  {
    name: "OPNsense proposal spelling, minimum (aes256-sha256-modp2048)",
    state: profile(MINIMUM),
    emulate: { A: { vendor: "opnsense" } },
    vendors: { A: "opnsense", B: "strongswan" },
    expect: "pass",
  },
  {
    name: "PAN-OS ↔ Azure, IKE GCM with group 20: PAN-OS uses PRF SHA-384, Azure SHA-384",
    state: profile(RECOMMENDED),
    // PAN-OS sends no integrity with IKE GCM and derives the PRF from the DH group.
    emulate: { A: { proposals: "aes256gcm16-prfsha384-ecp384" } },
    vendors: { A: "paloalto", B: "azure" },
    expect: "pass",
  },
  {
    name: "PAN-OS ↔ Azure, IKE GCM with group 19: PAN-OS PRF SHA-256 vs Azure SHA-384",
    state: profile(Object.assign({}, RECOMMENDED, { dh: 19, pfs: 19 })),
    emulate: { A: { proposals: "aes256gcm16-prfsha256-ecp256" }, B: { proposals: "aes256gcm16-prfsha384-ecp256" } },
    vendors: { A: "paloalto", B: "azure" },
    expect: "fail",
    why: "The tool flags this PRF mismatch as an error; the lab confirms the tunnel does not come up.",
  },
  {
    name: "Negative control: DH group mismatch (A group 20, B group 14)",
    state: profile(RECOMMENDED),
    emulate: { B: { proposals: "aes256gcm16-prfsha384-modp2048" } },
    expect: "fail",
    why: "Proves the lab detects a phase 1 mismatch.",
  },
  {
    name: "Negative control: ESP mismatch (A AES-GCM, B AES-CBC)",
    state: profile(RECOMMENDED),
    emulate: { B: { esp: "aes256-sha256-ecp384" } },
    expect: "fail",
    why: "Proves the lab detects a phase 2 mismatch.",
  },
];

module.exports = { FIXED, BASE, profile, RECOMMENDED, MINIMUM };
