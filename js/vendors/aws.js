/*
 * AWS Site-to-Site VPN
 * Rules: AWS Site-to-Site VPN User Guide (tunnel options, customer gateway requirements) and the
 * AWS CLI reference for modify-vpn-tunnel-options (verified 2026-10-26).
 * Terraform: aws_customer_gateway, aws_vpn_connection (tunnel1_* / tunnel2_*), aws_vpn_connection_route
 * (hashicorp/aws 6.x).
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    enc: { aes128: "AES128", aes256: "AES256", aes128gcm: "AES128-GCM-16", aes256gcm: "AES256-GCM-16" },
    int: { sha1: "SHA1", sha256: "SHA2-256", sha384: "SHA2-384", sha512: "SHA2-512" },
  };

  /* Valid values from the AWS CLI reference (modify-vpn-tunnel-options), also the provider's. */
  const VALID = {
    enc: ["AES128", "AES256", "AES128-GCM-16", "AES256-GCM-16"],
    int: ["SHA1", "SHA2-256", "SHA2-384", "SHA2-512"],
    dh1: [2, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
    dh2: [2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
  };

  /* AWS has no DPD retry count: one timeout, at least 30 s. */
  const dpdTimeout = (S) => Math.max(30, (S.dpdInt || 0) * (S.dpdRetry || 0));

  const isTgw = (me) => /^tgw-/.test((me.gw || "").trim());

  /* The peer's effective VPN type (the same rule as analyze.js). */
  function peerMode(S, k) {
    const o = k === "A" ? "B" : "A";
    const v = TM.vendor(S[o].vendor);
    return v.modes.includes(S[o].mode) ? S[o].mode : v.modes[0];
  }

  /* One selector pair per connection: the narrowed pair, or 0.0.0.0/0 both ways. */
  function selectors(c) {
    if (!c.eff.narrowed || c.pairs.length !== 1) return { local: "0.0.0.0/0", remote: "0.0.0.0/0" };
    const [mine, theirs] = c.pairs[0];
    // AWS calls the customer (peer) side "local" and the AWS side "remote"
    return { local: theirs.text, remote: mine.text };
  }

  function tunnelOptions(S) {
    return {
      p1enc: [N.enc[S.p1enc]],
      p1int: [N.int[S.p1int]],
      p1dh: [S.dh],
      p2enc: [N.enc[S.p2enc]],
      p2int: isGcm(S.p2enc) ? null : [N.int[S.p2int]],
      p2dh: [S.pfs],
    };
  }

  const hcl = (list) => "[" + list.map((x) => (typeof x === "number" ? x : `"${x}"`)).join(", ") + "]";

  function generateTerraform(c) {
    const S = c.S;
    const t = tunnelOptions(S);
    const sel = selectors(c);
    const lower = c.name.toLowerCase();
    const file = lower + ".tfvars";
    const tgw = isTgw(c.me);
    const head = [["region", c.me.loc || "<region>"], ["name", "vpn-" + lower]].concat(tgw
      ? [["transit_gateway_id", c.me.gw.trim()], ["tgw_route_table_id", "<tgw-route-table-id>"]]
      : [["vpn_gateway_id", (c.me.gw || "").trim() || "<vgw-id>"]]);
    const width = Math.max(...head.map(([key]) => key.length)); // terraform fmt alignment

    const vars = `# Site ${c.k}: AWS Site-to-Site VPN → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
${head.map(([key, val]) => `${key.padEnd(width)} = "${val}"`).join("\n")}

# The peer, represented as a customer gateway (static routing; the ASN is only a label here)
peer_public_ip = "${c.peer.ip}"
peer_bgp_asn   = 65000
peer_address_prefixes = [
${c.remote.map((r) => `  "${r.text}",`).join("\n")}
]

# Traffic selectors: AWS "local" is the customer side, "remote" the AWS side
local_ipv4_network_cidr  = "${sel.local}"
remote_ipv4_network_cidr = "${sel.remote}"

# vpn_shared_key is not set here: export TF_VAR_vpn_shared_key before plan/apply.

ike_versions                 = ["ikev2"]
phase1_encryption_algorithms = ${hcl(t.p1enc)}
phase1_integrity_algorithms  = ${hcl(t.p1int)}${isGcm(S.p1enc) ? " # used as PRF with GCM" : ""}
phase1_dh_group_numbers      = ${hcl(t.p1dh)}
phase1_lifetime_seconds      = ${S.p1life}
phase2_encryption_algorithms = ${hcl(t.p2enc)}
phase2_integrity_algorithms  = ${t.p2int ? hcl(t.p2int) : "[] # GCM carries its own integrity"}
phase2_dh_group_numbers      = ${hcl(t.p2dh)}
phase2_lifetime_seconds      = ${S.p2life}
dpd_timeout_seconds          = ${dpdTimeout(S)} # interval ${S.dpdInt} s × ${S.dpdRetry} retries
dpd_timeout_action           = "restart"
startup_action               = "start"

# Deploy:
#   export TF_VAR_vpn_shared_key='<pre-shared key>'   (8-64 characters: letters, digits, . and _; not starting with 0)
#   terraform init
#   terraform apply -var-file=${file}
# Then configure the peer for BOTH tunnels: terraform output tunnel1_address / tunnel2_address.`;

    const variables = `# variables.tf: inputs and allowed values (AWS CLI reference / hashicorp/aws 6.x)
variable "region" {
  type = string
}

variable "name" {
  description = "Name tag for the customer gateway and the VPN connection."
  type        = string
}

${tgw ? `variable "transit_gateway_id" {
  description = "Existing transit gateway (tgw-...)."
  type        = string
}

variable "tgw_route_table_id" {
  description = "Transit gateway route table for the static routes toward the peer."
  type        = string
}` : `variable "vpn_gateway_id" {
  description = "Existing virtual private gateway (vgw-...), attached to the VPC."
  type        = string
}`}

variable "peer_public_ip" {
  description = "Public IP of the peer VPN device."
  type        = string
}

variable "peer_bgp_asn" {
  type    = number
  default = 65000
}

variable "peer_address_prefixes" {
  description = "Networks behind the peer; one static route each."
  type        = list(string)
}

variable "local_ipv4_network_cidr" {
  description = "Traffic selector, customer side."
  type        = string
  default     = "0.0.0.0/0"
}

variable "remote_ipv4_network_cidr" {
  description = "Traffic selector, AWS side."
  type        = string
  default     = "0.0.0.0/0"
}

variable "vpn_shared_key" {
  description = "Pre-shared key for both tunnels. Set it with TF_VAR_vpn_shared_key, never in a file."
  type        = string
  sensitive   = true
  validation {
    condition     = can(regex("^[A-Za-z1-9._][A-Za-z0-9._]{7,63}$", var.vpn_shared_key))
    error_message = "AWS pre-shared keys are 8-64 characters (letters, digits, . and _) and cannot start with 0."
  }
}

variable "ike_versions" {
  type = list(string)
  validation {
    condition     = alltrue([for v in var.ike_versions : contains(["ikev1", "ikev2"], v)])
    error_message = "ike_versions: ikev1 | ikev2."
  }
}

variable "phase1_encryption_algorithms" {
  type = list(string)
  validation {
    condition     = alltrue([for v in var.phase1_encryption_algorithms : contains(${hcl(VALID.enc)}, v)])
    error_message = "phase1_encryption_algorithms: ${VALID.enc.join(" | ")}."
  }
}

variable "phase1_integrity_algorithms" {
  type = list(string)
  validation {
    condition     = alltrue([for v in var.phase1_integrity_algorithms : contains(${hcl(VALID.int)}, v)])
    error_message = "phase1_integrity_algorithms: ${VALID.int.join(" | ")}."
  }
}

variable "phase1_dh_group_numbers" {
  type = list(number)
  validation {
    condition     = alltrue([for v in var.phase1_dh_group_numbers : contains(${hcl(VALID.dh1)}, v)])
    error_message = "phase1_dh_group_numbers: ${VALID.dh1.join(" | ")}."
  }
}

variable "phase1_lifetime_seconds" {
  type = number
  validation {
    condition     = var.phase1_lifetime_seconds >= 900 && var.phase1_lifetime_seconds <= 28800
    error_message = "phase1_lifetime_seconds must be 900-28800."
  }
}

variable "phase2_encryption_algorithms" {
  type = list(string)
  validation {
    condition     = alltrue([for v in var.phase2_encryption_algorithms : contains(${hcl(VALID.enc)}, v)])
    error_message = "phase2_encryption_algorithms: ${VALID.enc.join(" | ")}."
  }
}

variable "phase2_integrity_algorithms" {
  type = list(string)
  validation {
    condition     = alltrue([for v in var.phase2_integrity_algorithms : contains(${hcl(VALID.int)}, v)])
    error_message = "phase2_integrity_algorithms: ${VALID.int.join(" | ")}."
  }
}

variable "phase2_dh_group_numbers" {
  type = list(number)
  validation {
    condition     = alltrue([for v in var.phase2_dh_group_numbers : contains(${hcl(VALID.dh2)}, v)])
    error_message = "phase2_dh_group_numbers: ${VALID.dh2.join(" | ")}."
  }
}

variable "phase2_lifetime_seconds" {
  type = number
  validation {
    condition     = var.phase2_lifetime_seconds >= 900 && var.phase2_lifetime_seconds <= 3600 && var.phase2_lifetime_seconds < var.phase1_lifetime_seconds
    error_message = "phase2_lifetime_seconds must be 900-3600 and below phase1_lifetime_seconds."
  }
}

variable "dpd_timeout_seconds" {
  type = number
  validation {
    condition     = var.dpd_timeout_seconds >= 30
    error_message = "dpd_timeout_seconds must be at least 30."
  }
}

variable "dpd_timeout_action" {
  type = string
  validation {
    condition     = contains(["clear", "none", "restart"], var.dpd_timeout_action)
    error_message = "dpd_timeout_action: clear | none | restart."
  }
}

variable "startup_action" {
  type = string
  validation {
    condition     = contains(["add", "start"], var.startup_action)
    error_message = "startup_action: add | start."
  }
}`;

    const tunnel = (n) => `  tunnel${n}_preshared_key                = var.vpn_shared_key
  tunnel${n}_ike_versions                 = var.ike_versions
  tunnel${n}_phase1_encryption_algorithms = var.phase1_encryption_algorithms
  tunnel${n}_phase1_integrity_algorithms  = var.phase1_integrity_algorithms
  tunnel${n}_phase1_dh_group_numbers      = var.phase1_dh_group_numbers
  tunnel${n}_phase1_lifetime_seconds      = var.phase1_lifetime_seconds
  tunnel${n}_phase2_encryption_algorithms = var.phase2_encryption_algorithms
  tunnel${n}_phase2_integrity_algorithms  = length(var.phase2_integrity_algorithms) > 0 ? var.phase2_integrity_algorithms : null
  tunnel${n}_phase2_dh_group_numbers      = var.phase2_dh_group_numbers
  tunnel${n}_phase2_lifetime_seconds      = var.phase2_lifetime_seconds
  tunnel${n}_dpd_timeout_seconds          = var.dpd_timeout_seconds
  tunnel${n}_dpd_timeout_action           = var.dpd_timeout_action
  tunnel${n}_startup_action               = var.startup_action`;

    const main = `# main.tf: customer gateway + static-route VPN connection (two tunnels) on an existing ${tgw ? "transit gateway" : "virtual private gateway"}
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_customer_gateway" "peer" {
  bgp_asn    = var.peer_bgp_asn
  ip_address = var.peer_public_ip
  type       = "ipsec.1"
  tags       = { Name = var.name }
}

# The pre-shared key ends up in the Terraform state (the provider has no write-only
# argument for it); keep the state encrypted and access-controlled.
resource "aws_vpn_connection" "this" {
  customer_gateway_id = aws_customer_gateway.peer.id
  ${tgw ? "transit_gateway_id  = var.transit_gateway_id" : "vpn_gateway_id      = var.vpn_gateway_id"}
  type                = "ipsec.1"
  static_routes_only  = true

  local_ipv4_network_cidr  = var.local_ipv4_network_cidr
  remote_ipv4_network_cidr = var.remote_ipv4_network_cidr

  # Both tunnels get the same settings; the peer must be configured for both.
${tunnel(1)}

${tunnel(2)}

  tags = { Name = var.name }
}

${tgw ? `# Static routes toward the peer in the transit gateway route table
resource "aws_ec2_transit_gateway_route" "peer" {
  for_each                       = toset(var.peer_address_prefixes)
  destination_cidr_block         = each.value
  transit_gateway_attachment_id  = aws_vpn_connection.this.transit_gateway_attachment_id
  transit_gateway_route_table_id = var.tgw_route_table_id
}` : `# Static routes toward the peer; enable route propagation from the virtual private
# gateway in the VPC route tables (aws_vpn_gateway_route_propagation) or add routes there.
resource "aws_vpn_connection_route" "peer" {
  for_each               = toset(var.peer_address_prefixes)
  destination_cidr_block = each.value
  vpn_connection_id      = aws_vpn_connection.this.id
}`}

output "tunnel1_address" {
  value = aws_vpn_connection.this.tunnel1_address
}

output "tunnel2_address" {
  value = aws_vpn_connection.this.tunnel2_address
}`;

    return [
      { title: file, text: vars },
      { title: "main.tf (resources)", text: main },
      { title: "variables.tf (inputs and allowed values)", text: variables },
    ];
  }

  /* AWS CLI: one shell script; the JSON options are the VpnConnectionOptionsSpecification. */
  function generate(c) {
    if (c.me.iac === "terraform") return generateTerraform(c);
    const S = c.S;
    const t = tunnelOptions(S);
    const sel = selectors(c);
    const lower = c.name.toLowerCase();
    const tgw = isTgw(c.me);
    const values = (list) => "[" + list.map((x) => (typeof x === "number" ? `{"Value": ${x}}` : `{"Value": "${x}"}`)).join(", ") + "]";

    const tunnelJson = `    {
      "PreSharedKey": "$VPN_PSK",
      "IKEVersions": [{"Value": "ikev2"}],
      "Phase1EncryptionAlgorithms": ${values(t.p1enc)},
      "Phase1IntegrityAlgorithms": ${values(t.p1int)},
      "Phase1DHGroupNumbers": ${values(t.p1dh)},
      "Phase1LifetimeSeconds": ${S.p1life},
      "Phase2EncryptionAlgorithms": ${values(t.p2enc)},${t.p2int ? `
      "Phase2IntegrityAlgorithms": ${values(t.p2int)},` : ""}
      "Phase2DHGroupNumbers": ${values(t.p2dh)},
      "Phase2LifetimeSeconds": ${S.p2life},
      "DPDTimeoutSeconds": ${dpdTimeout(S)},
      "DPDTimeoutAction": "restart",
      "StartupAction": "start"
    }`;

    const routes = tgw
      ? `# Static routes toward the peer in the transit gateway route table
ATTACH=$(aws ec2 describe-transit-gateway-attachments --region "$REGION" \\
  --filters Name=resource-id,Values="$VPN" --query 'TransitGatewayAttachments[0].TransitGatewayAttachmentId' --output text)
${c.remote.map((r) => `aws ec2 create-transit-gateway-route --region "$REGION" --transit-gateway-route-table-id "$TGW_RT" \\
  --destination-cidr-block ${r.text} --transit-gateway-attachment-id "$ATTACH"`).join("\n")}`
      : `# Static routes toward the peer (then enable route propagation from the VGW in the VPC route tables)
${c.remote.map((r) => `aws ec2 create-vpn-connection-route --region "$REGION" --vpn-connection-id "$VPN" --destination-cidr-block ${r.text}`).join("\n")}`;

    const script = `#!/bin/sh
# Site ${c.k}: AWS Site-to-Site VPN → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
# AWS CLI v2. Set the key first: export VPN_PSK='<pre-shared key>'
#   (8-64 characters: letters, digits, . and _; not starting with 0)
set -eu
REGION='${c.me.loc || "<region>"}'
${tgw ? `TGW='${c.me.gw.trim()}'
TGW_RT='<tgw-route-table-id>'` : `VGW='${(c.me.gw || "").trim() || "<vgw-id>"}'`}

# The peer, represented as a customer gateway (static routing; the ASN is only a label here)
CGW=$(aws ec2 create-customer-gateway --region "$REGION" --type ipsec.1 --public-ip ${c.peer.ip} --bgp-asn 65000 \\
  --tag-specifications 'ResourceType=customer-gateway,Tags=[{Key=Name,Value=cgw-${lower}}]' \\
  --query 'CustomerGateway.CustomerGatewayId' --output text)

# Both tunnels get the same settings; the peer must be configured for both.
# Traffic selectors: AWS "local" is the customer side, "remote" the AWS side.
OPTIONS=$(cat <<EOF
{
  "StaticRoutesOnly": true,
  "LocalIpv4NetworkCidr": "${sel.local}",
  "RemoteIpv4NetworkCidr": "${sel.remote}",
  "TunnelOptions": [
${tunnelJson},
${tunnelJson}
  ]
}
EOF
)

VPN=$(aws ec2 create-vpn-connection --region "$REGION" --type ipsec.1 --customer-gateway-id "$CGW" \\
  ${tgw ? '--transit-gateway-id "$TGW"' : '--vpn-gateway-id "$VGW"'} --options "$OPTIONS" \\
  --tag-specifications 'ResourceType=vpn-connection,Tags=[{Key=Name,Value=vpn-${lower}}]' \\
  --query 'VpnConnection.VpnConnectionId' --output text)
aws ec2 wait vpn-connection-available --region "$REGION" --vpn-connection-ids "$VPN"

${routes}

# The two tunnel addresses to configure on the peer:
aws ec2 describe-vpn-connections --region "$REGION" --vpn-connection-ids "$VPN" \\
  --query 'VpnConnections[0].VgwTelemetry[].OutsideIpAddress' --output text`;

    return [{ title: `aws-vpn-${lower}.sh`, text: script }];
  }

  function checks({ S, k, A, B, add }) {
    const me = S[k];
    const o = k === "A" ? "B" : "A";
    if (S.p1life < 900 || S.p1life > 28800) add("err", `AWS (site ${k}): the phase 1 lifetime must be 900–28,800 s.`);
    if (S.p2life < 900 || S.p2life > 3600) add("err", `AWS (site ${k}): the phase 2 lifetime must be 900–3,600 s.`);
    else if (S.p2life >= S.p1life) add("err", `AWS (site ${k}): the phase 2 lifetime must be below the phase 1 lifetime.`);
    if (S.p2kb) add("info", `AWS (site ${k}) has no data-volume lifetime; only the time limit applies.`);

    const raw = S.dpdInt * S.dpdRetry;
    if (raw < 30) add("warn", `AWS DPD timeout must be at least 30 s; interval × retries is ${raw} s, so the config uses 30 s.`);

    const pairs = A.nets.length * B.nets.length;
    if (peerMode(S, k) === "policy" && pairs > 1)
      add("err", `AWS (site ${k}) carries one SA pair per tunnel, but site ${o} is policy-based with ${pairs} subnet pairs, which become ${pairs} SAs. Summarize each side into one CIDR, or make site ${o} route-based.`);

    if (!me.loc) add("warn", `AWS (site ${k}): no region set.`);
    const gw = (me.gw || "").trim();
    if (gw && !/^(vgw|tgw)-[0-9a-f]+$/.test(gw))
      add("warn", `AWS (site ${k}): the gateway should be a virtual private gateway (vgw-…) or transit gateway (tgw-…) ID.`);
  }

  function notes({ S, add }) {
    add("info", "AWS: every VPN connection has two tunnels with different outside IPs. Configure the peer for both (the tool's peer config covers the AWS address entered as the public IP; repeat it for the second tunnel address).");
    add("info", "AWS pre-shared keys: 8–64 characters, letters, digits, . and _ only, not starting with 0.");
  }

  TM.register({
    id: "aws",
    order: 1.1,
    label: "AWS Site-to-Site VPN",
    short: "AWS",
    modes: ["route"],
    narrow: true, // local/remote_ipv4_network_cidr, one pair
    supports: {
      p1enc: ["aes128", "aes256", "aes128gcm", "aes256gcm"],
      p1int: ["sha1", "sha256", "sha384", "sha512"],
      dh: [2, 14, 15, 19, 20, 21, 24],
      p2enc: ["aes128", "aes256", "aes128gcm", "aes256gcm"],
      p2int: ["sha1", "sha256", "sha384", "sha512"],
      pfs: [2, 5, 14, 15, 19, 20, 21, 24],
    },
    fields: {
      gw: ["VPN gateway ID", "vgw-… or tgw-…"],
      loc: ["Region", "eu-north-1"],
      iac: [["cli", "AWS CLI (shell script)"], ["terraform", "Terraform (aws)"]],
    },
    hint: "AWS is route-based with static routes. Against a policy-based peer it narrows the selectors to one subnet pair; enter the AWS tunnel 1 outside IP as the public IP.",
    dpdTimeout,
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: String(S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? "(GCM)" : spell(N.int, S.p2int),
      pfs: S.pfs ? String(S.pfs) : "(required)",
      dpd: `DPDTimeoutSeconds ${dpdTimeout(S)}`,
    }),
    narrowNote: "AWS: LocalIpv4NetworkCidr / RemoteIpv4NetworkCidr (one pair).",
    pdfNote: (S) =>
      [`AWS Site-to-Site VPN has two tunnels per connection; the peer needs both. DPD timeout ${dpdTimeout(S)} s (no separate retry count); AWS starts the tunnel (StartupAction start) and restarts it after a DPD timeout.`],
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-26",
      used: "Allowed phase 1/2 algorithms and DH groups, lifetime ranges (900–28,800 s and 900–3,600 s, phase 2 below phase 1), DPD timeout ≥ 30 s and actions, startup action, PFS required, one SA pair per tunnel (policy-based peers limited to one SA), two tunnels per connection, pre-shared key rules. Terraform uses aws_vpn_connection tunnel1_*/tunnel2_* arguments (hashicorp/aws 6.x).",
      links: [
        ["AWS: Tunnel options for your Site-to-Site VPN connection", "https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html"],
        ["AWS: Requirements for a customer gateway device", "https://docs.aws.amazon.com/vpn/latest/s2svpn/CGRequirements.html"],
        ["AWS CLI: modify-vpn-tunnel-options (valid values)", "https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-vpn-tunnel-options.html"],
        ["Terraform aws: aws_vpn_connection", "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpn_connection"],
      ],
    },
  });
})();
