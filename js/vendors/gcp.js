/*
 * Google Cloud VPN (Classic VPN, static routing)
 * Rules: Cloud VPN docs, supported IKE ciphers, networks and tunnel routing, Classic VPN
 * deprecations (verified 2026-10-26). HA VPN needs BGP, which the tool does not generate;
 * Classic VPN with static routing is still supported for on-premises peers.
 * gcloud: compute target-vpn-gateways / forwarding-rules / vpn-tunnels (--phase1-* / --phase2-*).
 * Terraform: google_compute_vpn_gateway (Classic), google_compute_vpn_tunnel cipher_suite and
 * shared_secret_wo (hashicorp/google 8.x).
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  /* Cipher names as on the supported-ciphers page and in the provider's examples. */
  const N = {
    enc: { aes128: "AES-CBC-128", aes192: "AES-CBC-192", aes256: "AES-CBC-256", "3des": "3DES-CBC", aes128gcm: "AES-GCM-16-128", aes256gcm: "AES-GCM-16-256" },
    int: { sha1: "HMAC-SHA1-96", md5: "HMAC-MD5-96", sha256: "HMAC-SHA2-256-128", sha384: "HMAC-SHA2-384-192", sha512: "HMAC-SHA2-512-256" },
    prf: { sha1: "PRF-HMAC-SHA1", md5: "PRF-HMAC-MD5", sha256: "PRF-HMAC-SHA2-256", sha384: "PRF-HMAC-SHA2-384", sha512: "PRF-HMAC-SHA2-512" },
    dh: (n) => "Group-" + n,
  };

  /* Cloud VPN's fixed lifetimes; Google recommends the peer match them exactly. */
  const LIFE1 = 36000, LIFE2 = 10800;

  const res = (c) => ("vpn-" + c.name.toLowerCase()).slice(0, 50);

  function peerMode(S, k) {
    const o = k === "A" ? "B" : "A";
    const v = TM.vendor(S[o].vendor);
    return v.modes.includes(S[o].mode) ? S[o].mode : v.modes[0];
  }

  /* One child SA per tunnel: the narrowed pair, or 0.0.0.0/0 both ways (route-based). */
  function selectors(c) {
    if (!c.eff.narrowed || c.pairs.length !== 1) return { local: "0.0.0.0/0", remote: "0.0.0.0/0" };
    const [mine, theirs] = c.pairs[0];
    return { local: mine.text, remote: theirs.text };
  }

  function ciphers(S) {
    return {
      p1enc: N.enc[S.p1enc],
      p1int: isGcm(S.p1enc) ? null : N.int[S.p1int],
      p1prf: N.prf[S.p1int],
      p1dh: N.dh(S.dh),
      p2enc: N.enc[S.p2enc],
      p2int: isGcm(S.p2enc) ? null : N.int[S.p2int],
      p2pfs: N.dh(S.pfs),
    };
  }

  const hcl = (list) => "[" + list.map((x) => `"${x}"`).join(", ") + "]";

  function generateTerraform(c) {
    const S = c.S;
    const x = ciphers(S);
    const sel = selectors(c);
    const name = res(c);
    const file = c.name.toLowerCase() + ".tfvars";

    const vars = `# Site ${c.k}: Google Cloud VPN (Classic, static routing) → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
project = "${c.me.rg || "<project-id>"}"
region  = "${c.me.loc || "<region>"}"
network = "${c.me.gw || "<vpc-network>"}"
name    = "${name}"

peer_public_ip = "${c.peer.ip}"
peer_address_prefixes = [
${c.remote.map((r) => `  "${r.text}",`).join("\n")}
]

# One child SA per tunnel: ${sel.local === "0.0.0.0/0" ? "route-based, 0.0.0.0/0 both ways" : "the single subnet pair"}
local_traffic_selector  = ["${sel.local}"]
remote_traffic_selector = ["${sel.remote}"]

# vpn_shared_key is not set here: export TF_VAR_vpn_shared_key before plan/apply.

phase1_encryption = ${hcl([x.p1enc])}
phase1_integrity  = ${x.p1int ? hcl([x.p1int]) : "[] # GCM carries its own integrity"}
phase1_prf        = ${hcl([x.p1prf])}
phase1_dh         = ${hcl([x.p1dh])}
phase2_encryption = ${hcl([x.p2enc])}
phase2_integrity  = ${x.p2int ? hcl([x.p2int]) : "[] # GCM carries its own integrity"}
phase2_pfs        = ${hcl([x.p2pfs])}

# Deploy:
#   export TF_VAR_vpn_shared_key='<pre-shared key>'
#   terraform init
#   terraform apply -var-file=${file}
# Cloud VPN uses fixed lifetimes: 36,000 s (IKE) and 10,800 s (child SA).`;

    const variables = `# variables.tf: inputs (hashicorp/google 8.x)
variable "project" {
  type = string
}

variable "region" {
  type = string
}

variable "network" {
  description = "Existing VPC network."
  type        = string
}

variable "name" {
  description = "Name prefix for the gateway, its address, forwarding rules, tunnel and routes."
  type        = string
  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,48}[a-z0-9])?$", var.name))
    error_message = "name must be lowercase letters, digits and hyphens, starting with a letter."
  }
}

variable "peer_public_ip" {
  type = string
}

variable "peer_address_prefixes" {
  description = "Networks behind the peer; one static route each."
  type        = list(string)
}

variable "local_traffic_selector" {
  type = list(string)
}

variable "remote_traffic_selector" {
  type = list(string)
}

variable "vpn_shared_key" {
  description = "Pre-shared key. Set it with TF_VAR_vpn_shared_key; it is sent write-only and never stored in state."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "phase1_encryption" {
  type = list(string)
}

variable "phase1_integrity" {
  type = list(string)
}

variable "phase1_prf" {
  type = list(string)
}

variable "phase1_dh" {
  type = list(string)
}

variable "phase2_encryption" {
  type = list(string)
}

variable "phase2_integrity" {
  type = list(string)
}

variable "phase2_pfs" {
  type = list(string)
}`;

    const main = `# main.tf: Classic VPN gateway, its address and forwarding rules, one tunnel and static routes
terraform {
  required_version = ">= 1.11" # write-only shared_secret_wo
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

data "google_compute_network" "vpc" {
  name = var.network
}

resource "google_compute_address" "vpn" {
  name = "\${var.name}-ip"
}

resource "google_compute_vpn_gateway" "this" {
  name    = var.name
  network = data.google_compute_network.vpc.id
}

resource "google_compute_forwarding_rule" "esp" {
  name        = "\${var.name}-esp"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.vpn.address
  target      = google_compute_vpn_gateway.this.id
}

resource "google_compute_forwarding_rule" "udp500" {
  name        = "\${var.name}-udp500"
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.vpn.address
  target      = google_compute_vpn_gateway.this.id
}

resource "google_compute_forwarding_rule" "udp4500" {
  name        = "\${var.name}-udp4500"
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.vpn.address
  target      = google_compute_vpn_gateway.this.id
}

resource "google_compute_vpn_tunnel" "this" {
  name                     = var.name
  peer_ip                  = var.peer_public_ip
  ike_version              = 2
  shared_secret_wo         = var.vpn_shared_key
  shared_secret_wo_version = 1 # raise to push a new key
  target_vpn_gateway       = google_compute_vpn_gateway.this.id

  local_traffic_selector  = var.local_traffic_selector
  remote_traffic_selector = var.remote_traffic_selector

  cipher_suite {
    phase1 {
      encryption = var.phase1_encryption
      integrity  = length(var.phase1_integrity) > 0 ? var.phase1_integrity : null
      prf        = var.phase1_prf
      dh         = var.phase1_dh
    }
    phase2 {
      encryption = var.phase2_encryption
      integrity  = length(var.phase2_integrity) > 0 ? var.phase2_integrity : null
      pfs        = var.phase2_pfs
    }
  }

  depends_on = [
    google_compute_forwarding_rule.esp,
    google_compute_forwarding_rule.udp500,
    google_compute_forwarding_rule.udp4500,
  ]
}

resource "google_compute_route" "peer" {
  for_each            = toset(var.peer_address_prefixes)
  name                = "\${var.name}-\${replace(each.value, "/[./]/", "-")}"
  network             = data.google_compute_network.vpc.name
  dest_range          = each.value
  priority            = 1000
  next_hop_vpn_tunnel = google_compute_vpn_tunnel.this.id
}

output "gateway_ip" {
  description = "Cloud VPN address: the public IP the peer connects to."
  value       = google_compute_address.vpn.address
}`;

    return [
      { title: file, text: vars },
      { title: "main.tf (resources)", text: main },
      { title: "variables.tf (inputs)", text: variables },
    ];
  }

  function generate(c) {
    if (c.me.iac === "terraform") return generateTerraform(c);
    const S = c.S;
    const x = ciphers(S);
    const sel = selectors(c);
    const name = res(c);

    const script = `#!/bin/sh
# Site ${c.k}: Google Cloud VPN (Classic, static routing) → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
# Set the key first: export VPN_PSK='<pre-shared key>'
set -eu
PROJECT='${c.me.rg || "<project-id>"}'
REGION='${c.me.loc || "<region>"}'
NETWORK='${c.me.gw || "<vpc-network>"}'
NAME='${name}'
gcloud config set project "$PROJECT"

# Gateway, its static address and the forwarding rules for ESP, UDP 500 and UDP 4500
gcloud compute addresses create "$NAME-ip" --region "$REGION"
IP=$(gcloud compute addresses describe "$NAME-ip" --region "$REGION" --format 'value(address)')
gcloud compute target-vpn-gateways create "$NAME" --network "$NETWORK" --region "$REGION"
gcloud compute forwarding-rules create "$NAME-esp" --region "$REGION" --ip-protocol ESP --address "$IP" --target-vpn-gateway "$NAME"
gcloud compute forwarding-rules create "$NAME-udp500" --region "$REGION" --ip-protocol UDP --ports 500 --address "$IP" --target-vpn-gateway "$NAME"
gcloud compute forwarding-rules create "$NAME-udp4500" --region "$REGION" --ip-protocol UDP --ports 4500 --address "$IP" --target-vpn-gateway "$NAME"

# The tunnel: one child SA (${sel.local === "0.0.0.0/0" ? "route-based, 0.0.0.0/0 both ways" : "the single subnet pair"})
gcloud compute vpn-tunnels create "$NAME" --region "$REGION" --target-vpn-gateway "$NAME" \\
  --peer-address ${c.peer.ip} --ike-version 2 --shared-secret "$VPN_PSK" \\
  --local-traffic-selector ${sel.local} --remote-traffic-selector ${sel.remote} \\
  --phase1-encryption ${x.p1enc}${x.p1int ? ` --phase1-integrity ${x.p1int}` : ""} --phase1-prf ${x.p1prf} --phase1-dh ${x.p1dh} \\
  --phase2-encryption ${x.p2enc}${x.p2int ? ` --phase2-integrity ${x.p2int}` : ""} --phase2-pfs ${x.p2pfs}

# Static routes toward the peer
${c.remote.map((r) => `gcloud compute routes create "$NAME-${r.text.replace(/[./]/g, "-")}" --network "$NETWORK" --destination-range ${r.text} \\
  --next-hop-vpn-tunnel "$NAME" --next-hop-vpn-tunnel-region "$REGION"`).join("\n")}

echo "Cloud VPN address for the peer: $IP"
# Cloud VPN uses fixed lifetimes: 36,000 s (IKE) and 10,800 s (child SA).`;

    return [{ title: `gcp-vpn-${c.name.toLowerCase()}.sh`, text: script }];
  }

  function checks({ S, k, A, B, add }) {
    const me = S[k];
    const o = k === "A" ? "B" : "A";
    if (S.p1life !== LIFE1 || S.p2life !== LIFE2)
      add("warn", `Google Cloud (site ${k}) uses fixed lifetimes of ${LIFE1.toLocaleString("en")} s (IKE) and ${LIFE2.toLocaleString("en")} s (child SA). Google recommends setting the peer to exactly these values.`);
    if (S.p2kb) add("info", `Google Cloud (site ${k}) has no data-volume lifetime; only the time limit applies.`);

    const pairs = A.nets.length * B.nets.length;
    if (peerMode(S, k) === "policy" && pairs > 1)
      add("err", `Google Cloud VPN (site ${k}) always uses a single child SA per tunnel, but site ${o} is policy-based with ${pairs} subnet pairs, which become ${pairs} SAs. Summarize each side into one CIDR, or make site ${o} route-based.`);

    if (!me.rg) add("warn", `Google Cloud (site ${k}): no project ID set.`);
    if (!me.loc) add("warn", `Google Cloud (site ${k}): no region set.`);
  }

  function notes({ add }) {
    add("info", "Google Cloud: this is a Classic VPN gateway with static routing, since HA VPN requires BGP. Cloud VPN's DPD interval is not configurable; enable IKEv2 fragmentation on the peer, as Google recommends.");
  }

  TM.register({
    id: "gcp",
    order: 1.2,
    label: "Google Cloud VPN (Classic, static)",
    short: "Google Cloud",
    modes: ["route"],
    narrow: true, // local/remote traffic selector, one pair
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p1int: ["sha1", "sha256", "sha384", "sha512", "md5"],
      dh: [2, 5, 14, 15, 19, 20, 21, 24],
      p2enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm"],
      p2int: ["sha1", "sha256", "sha512"],
      pfs: [2, 5, 14, 15, 19, 20, 21, 24],
    },
    fields: {
      rg: ["Project ID", "my-project"],
      gw: ["VPC network", "default"],
      loc: ["Region", "europe-north1"],
      iac: [["gcloud", "gcloud (shell script)"], ["terraform", "Terraform (google)"]],
    },
    hint: "Classic VPN with static routing (HA VPN needs BGP). Route-based; against a policy-based peer it narrows the selectors to one subnet pair. Enter the gateway's reserved address as the public IP.",
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: isGcm(S.p1enc) ? spell(N.prf, S.p1int) : `${spell(N.int, S.p1int)} / ${spell(N.prf, S.p1int)}`,
      dh: N.dh(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM)" : spell(N.int, S.p2int),
      pfs: S.pfs ? N.dh(S.pfs) : "(required)",
      dpd: "fixed (not configurable)",
    }),
    narrowNote: "Google Cloud: local/remote traffic selector (one pair).",
    pdfNote: () => [`Google Cloud VPN uses fixed lifetimes of ${LIFE1} s (IKE) and ${LIFE2} s (child SA) and a fixed DPD interval.`],
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-26",
      used: "Supported IKEv2 ciphers per phase (phase 2 without 3DES and SHA-384), PFS required, fixed lifetimes 36,000 s / 10,800 s, one child SA per tunnel, Classic VPN static routing still supported (BGP deprecated 2025-08-01), DPD not configurable, IKE fragmentation. gcloud uses vpn-tunnels create --phase1-*/--phase2-*; Terraform uses google_compute_vpn_tunnel cipher_suite and shared_secret_wo (hashicorp/google 8.x).",
      links: [
        ["Google Cloud: Supported IKE ciphers", "https://cloud.google.com/network-connectivity/docs/vpn/concepts/supported-ike-ciphers"],
        ["Google Cloud: Networks and tunnel routing", "https://cloud.google.com/network-connectivity/docs/vpn/concepts/choosing-networks-routing"],
        ["Google Cloud: Classic VPN deprecations", "https://cloud.google.com/network-connectivity/docs/vpn/deprecations"],
        ["gcloud compute vpn-tunnels create", "https://cloud.google.com/sdk/gcloud/reference/compute/vpn-tunnels/create"],
        ["Terraform google: google_compute_vpn_tunnel", "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_vpn_tunnel"],
      ],
    },
  });
})();
