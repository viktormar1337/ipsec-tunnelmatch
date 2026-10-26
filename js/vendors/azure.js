/*
 * Microsoft Azure VPN Gateway
 * Rules: Microsoft Learn, custom IPsec/IKE connection policies (verified 2026-10-19).
 * Bicep: parameter names and allowed values follow AVM avm/res/network/connection 0.1.7.
 * Terraform: azurerm_virtual_network_gateway_connection (azurerm 4.x), same inputs as the Bicep file.
 */
(function () {
  "use strict";
  const { isGcm, spell } = TM;

  const N = {
    enc: { aes128: "AES128", aes192: "AES192", aes256: "AES256", aes128gcm: "GCMAES128", aes256gcm: "GCMAES256", "3des": "DES3" },
    int: { sha1: "SHA1", sha256: "SHA256", sha384: "SHA384", sha512: "SHA512", md5: "MD5" },
    dh: { 2: "DHGroup2", 14: "DHGroup14", 19: "ECP256", 20: "ECP384", 24: "DHGroup24" },
    pfs: { 0: "None", 2: "PFS2", 14: "PFS2048", 19: "ECP256", 20: "ECP384", 24: "PFS24" },
  };

  /* Allowed values copied from AVM network/connection 0.1.7 (customIPSecPolicyType and @allowed params). */
  const AVM = {
    ipsecEncryption: ["None", "DES", "DES3", "AES128", "AES192", "AES256", "GCMAES128", "GCMAES192", "GCMAES256"],
    ipsecIntegrity: ["MD5", "SHA1", "SHA256", "GCMAES128", "GCMAES192", "GCMAES256"],
    ikeEncryption: ["DES", "DES3", "AES128", "AES192", "AES256", "GCMAES256", "GCMAES128"],
    ikeIntegrity: ["MD5", "SHA1", "SHA256", "SHA384", "GCMAES256", "GCMAES128"],
    dhGroup: ["None", "DHGroup1", "DHGroup2", "DHGroup14", "DHGroup2048", "ECP256", "ECP384", "DHGroup24"],
    pfsGroup: ["None", "PFS1", "PFS2", "PFS2048", "ECP256", "ECP384", "PFS24", "PFS14", "PFSMM"],
    connectionMode: ["Default", "InitiatorOnly", "ResponderOnly"],
  };

  /* Allowed values in the azurerm provider (azurerm_virtual_network_gateway_connection ipsec_policy).
     Same set as AVM; checked against the provider docs 2026-10-21. */
  const TF = {
    dhGroup: ["DHGroup1", "DHGroup14", "DHGroup2", "DHGroup2048", "DHGroup24", "ECP256", "ECP384", "None"],
    pfsGroup: ["ECP256", "ECP384", "PFS1", "PFS14", "PFS2", "PFS2048", "PFS24", "PFSMM", "None"],
  };

  /* Azure has no DPD retry count: timeout = interval × retries, clamped to 9–3600 s. */
  const dpdTimeout = (S) => Math.min(3600, Math.max(9, (S.dpdInt || 0) * (S.dpdRetry || 0)));

  function policy(S) {
    const ns = "(not supported)";
    return {
      saLifeTimeSeconds: S.p2life,
      saDataSizeKilobytes: S.p2kb || 102400000,
      ipsecEncryption: N.enc[S.p2enc] || ns,
      ipsecIntegrity: isGcm(S.p2enc) ? N.enc[S.p2enc] : N.int[S.p2int] || ns,
      ikeEncryption: N.enc[S.p1enc] || ns,
      ikeIntegrity: N.int[S.p1int] || ns,
      dhGroup: N.dh[S.dh] || ns,
      pfsGroup: N.pfs[S.pfs] || ns,
    };
  }

  const quoteUnion = (list) => list.map((x) => `'${x}'`).join(" | ");

  /* Terraform (azurerm 4.x): the same inputs as the Bicep parameter file, in snake_case. */
  const hcl = (list) => "[" + list.map((x) => `"${x}"`).join(", ") + "]";

  function generateTerraform(c) {
    const S = c.S;
    const pol = policy(S);
    const usePB = c.eff.narrowed;
    const lower = c.name.toLowerCase();
    const file = lower + ".tfvars";

    const tsp = usePB
      ? "\n" + c.pairs.map(([l, r]) => `  {
    local_address_ranges  = ["${l.text}"]
    remote_address_ranges = ["${r.text}"]
  },`).join("\n") + "\n"
      : "";

    const vars = `# Site ${c.k}: Azure VPN Gateway → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
# Same inputs as the Bicep parameter file, in Terraform naming.
resource_group_name        = "${c.me.rg || "<resource-group>"}"
vpn_gateway_name           = "${c.me.gw || "<vpn-gateway>"}"
location                   = "${c.me.loc || "<region>"}"
local_network_gateway_name = "lng-${lower}"
name                       = "cn-${lower}"

# The peer, represented as a local network gateway
peer_public_ip = "${c.peer.ip}"
peer_address_prefixes = [
${c.remote.map((r) => `  "${r.text}",`).join("\n")}
]

# vpn_shared_key is not set here: export TF_VAR_vpn_shared_key before plan/apply.

connection_type                    = "IPsec"
connection_mode                    = "${c.me.cmode || "Default"}"
connection_protocol                = "IKEv2"
dpd_timeout_seconds                = ${dpdTimeout(S)} # interval ${S.dpdInt} s × ${S.dpdRetry} retries
use_policy_based_traffic_selectors = ${usePB}

traffic_selector_policies = [${tsp}]

custom_ipsec_policy = {
  sa_lifetime_seconds    = ${pol.saLifeTimeSeconds}
  sa_data_size_kilobytes = ${pol.saDataSizeKilobytes}
  ipsec_encryption       = "${pol.ipsecEncryption}"
  ipsec_integrity        = "${pol.ipsecIntegrity}"
  ike_encryption         = "${pol.ikeEncryption}"
  ike_integrity          = "${pol.ikeIntegrity}"${isGcm(S.p1enc) ? " # used as PRF with GCM" : ""}
  dh_group               = "${pol.dhGroup}"
  pfs_group              = "${pol.pfsGroup}"
}

# Deploy:
#   export TF_VAR_vpn_shared_key='<pre-shared key>'   (PowerShell: $env:TF_VAR_vpn_shared_key = '...')
#   export ARM_SUBSCRIPTION_ID='<subscription-id>'
#   terraform init
#   terraform apply -var-file=${file}
# The IKE SA lifetime is fixed at 28,800 s on Azure VPN gateways.`;

    const variables = `# variables.tf: inputs and allowed values (same as the Bicep template and AVM connection 0.1.7)
variable "resource_group_name" {
  description = "Resource group of the existing VPN gateway; the new resources go here too."
  type        = string
}

variable "vpn_gateway_name" {
  description = "Name of the existing route-based VPN gateway (VpnGw1+ SKU)."
  type        = string
}

variable "location" {
  description = "Location for the new resources."
  type        = string
}

variable "local_network_gateway_name" {
  description = "Name of the local network gateway that represents the peer."
  type        = string
}

variable "name" {
  description = "Connection name."
  type        = string
}

variable "peer_public_ip" {
  description = "Public IP of the peer VPN device."
  type        = string
}

variable "peer_address_prefixes" {
  description = "Address prefixes behind the peer."
  type        = list(string)
}

variable "vpn_shared_key" {
  description = "VPN shared key. Set it with TF_VAR_vpn_shared_key, never in a file."
  type        = string
  sensitive   = true
}

variable "connection_type" {
  type    = string
  default = "IPsec"
  validation {
    condition     = contains(["IPsec"], var.connection_type)
    error_message = "connection_type must be IPsec."
  }
}

variable "connection_mode" {
  type    = string
  default = "Default"
  validation {
    condition     = contains(${hcl(AVM.connectionMode)}, var.connection_mode)
    error_message = "connection_mode must be Default, InitiatorOnly or ResponderOnly."
  }
}

variable "connection_protocol" {
  type    = string
  default = "IKEv2"
  validation {
    condition     = contains(["IKEv1", "IKEv2"], var.connection_protocol)
    error_message = "connection_protocol must be IKEv1 or IKEv2."
  }
}

variable "dpd_timeout_seconds" {
  type    = number
  default = 45
  validation {
    condition     = var.dpd_timeout_seconds >= 9 && var.dpd_timeout_seconds <= 3600
    error_message = "dpd_timeout_seconds must be 9-3600."
  }
}

variable "use_policy_based_traffic_selectors" {
  type    = bool
  default = false
}

variable "traffic_selector_policies" {
  type = list(object({
    local_address_ranges  = list(string)
    remote_address_ranges = list(string)
  }))
  default = []
}

variable "custom_ipsec_policy" {
  description = "The custom IPsec/IKE policy for this connection."
  type = object({
    sa_lifetime_seconds    = number
    sa_data_size_kilobytes = number
    ipsec_encryption       = string
    ipsec_integrity        = string
    ike_encryption         = string
    ike_integrity          = string
    dh_group               = string
    pfs_group              = string
  })
  validation {
    condition = (
      var.custom_ipsec_policy.sa_lifetime_seconds >= 300 &&
      var.custom_ipsec_policy.sa_data_size_kilobytes >= 1024 &&
      contains(${hcl(AVM.ipsecEncryption)}, var.custom_ipsec_policy.ipsec_encryption) &&
      contains(${hcl(AVM.ipsecIntegrity)}, var.custom_ipsec_policy.ipsec_integrity) &&
      contains(${hcl(AVM.ikeEncryption)}, var.custom_ipsec_policy.ike_encryption) &&
      contains(${hcl(AVM.ikeIntegrity)}, var.custom_ipsec_policy.ike_integrity) &&
      contains(${hcl(TF.dhGroup)}, var.custom_ipsec_policy.dh_group) &&
      contains(${hcl(TF.pfsGroup)}, var.custom_ipsec_policy.pfs_group)
    )
    error_message = "custom_ipsec_policy has a value the azurerm provider does not allow (or a lifetime below 300 s / 1024 KB)."
  }
}`;

    const main = `# main.tf: local network gateway + IPsec connection on an existing VPN gateway (azurerm 4.x)
terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  # azurerm 4.x needs a subscription: ARM_SUBSCRIPTION_ID or subscription_id = "..."
}

data "azurerm_virtual_network_gateway" "vpn" {
  name                = var.vpn_gateway_name
  resource_group_name = var.resource_group_name
}

resource "azurerm_local_network_gateway" "peer" {
  name                = var.local_network_gateway_name
  location            = var.location
  resource_group_name = var.resource_group_name
  gateway_address     = var.peer_public_ip
  address_space       = var.peer_address_prefixes
}

resource "azurerm_virtual_network_gateway_connection" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name

  type                       = var.connection_type
  connection_mode            = var.connection_mode
  connection_protocol        = var.connection_protocol
  dpd_timeout_seconds        = var.dpd_timeout_seconds
  virtual_network_gateway_id = data.azurerm_virtual_network_gateway.vpn.id
  local_network_gateway_id   = azurerm_local_network_gateway.peer.id
  shared_key                 = var.vpn_shared_key

  use_policy_based_traffic_selectors = var.use_policy_based_traffic_selectors

  ipsec_policy {
    sa_lifetime      = var.custom_ipsec_policy.sa_lifetime_seconds
    sa_datasize      = var.custom_ipsec_policy.sa_data_size_kilobytes
    ipsec_encryption = var.custom_ipsec_policy.ipsec_encryption
    ipsec_integrity  = var.custom_ipsec_policy.ipsec_integrity
    ike_encryption   = var.custom_ipsec_policy.ike_encryption
    ike_integrity    = var.custom_ipsec_policy.ike_integrity
    dh_group         = var.custom_ipsec_policy.dh_group
    pfs_group        = var.custom_ipsec_policy.pfs_group
  }

  dynamic "traffic_selector_policy" {
    for_each = var.traffic_selector_policies
    content {
      local_address_cidrs  = traffic_selector_policy.value.local_address_ranges
      remote_address_cidrs = traffic_selector_policy.value.remote_address_ranges
    }
  }
}

output "resource_id" {
  value = azurerm_virtual_network_gateway_connection.this.id
}

output "name" {
  value = azurerm_virtual_network_gateway_connection.this.name
}`;

    return [
      { title: file, text: vars },
      { title: "main.tf (resources)", text: main },
      { title: "variables.tf (inputs and allowed values)", text: variables },
    ];
  }

  function generate(c) {
    if (c.me.iac === "terraform") return generateTerraform(c);
    const S = c.S;
    const pol = policy(S);
    const usePB = c.eff.narrowed;
    const lower = c.name.toLowerCase();
    const file = lower + ".bicepparam";
    const rg = c.me.rg || "<resource-group>";
    const typesPath = (c.me.types || "").trim() || "<types-file>";

    const tsp = usePB
      ? c.pairs.map(([l, r]) => `  {
    localAddressRanges: [
      '${l.text}'
    ]
    remoteAddressRanges: [
      '${r.text}'
    ]
  }`).join("\n")
      : "";

    const params = `using './main.bicep'

// Site ${c.k}: Azure VPN Gateway → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
// Parameter names and allowed values follow avm/res/network/connection 0.1.7
param vpnGatewayName = '${c.me.gw || "<vpn-gateway>"}'
param location = '${c.me.loc || "<region>"}'
param localNetworkGatewayName = 'lng-${lower}'
param name = 'cn-${lower}'

// The peer, represented as a local network gateway
param peerPublicIp = '${c.peer.ip}'
param peerAddressPrefixes = [
${c.remote.map((r) => `  '${r.text}'`).join("\n")}
]

// Keep the key out of source control: set VPN_PSK before deploying,
// or swap for az.getSecret('<sub-id>', '<kv-rg>', '<kv-name>', '<secret-name>')
param vpnSharedKey = readEnvironmentVariable('VPN_PSK')

param connectionType = 'IPsec'
param connectionMode = '${c.me.cmode || "Default"}'
param connectionProtocol = 'IKEv2'
param dpdTimeoutSeconds = ${dpdTimeout(S)} // interval ${S.dpdInt} s × ${S.dpdRetry} retries
param usePolicyBasedTrafficSelectors = ${usePB}
param trafficSelectorPolicies = [${usePB ? "\n" + tsp + "\n" : ""}]

param customIPSecPolicy = {
  saLifeTimeSeconds: ${pol.saLifeTimeSeconds}
  saDataSizeKilobytes: ${pol.saDataSizeKilobytes}
  ipsecEncryption: '${pol.ipsecEncryption}'
  ipsecIntegrity: '${pol.ipsecIntegrity}'
  ikeEncryption: '${pol.ikeEncryption}'
  ikeIntegrity: '${pol.ikeIntegrity}'${isGcm(S.p1enc) ? " // used as PRF with GCM" : ""}
  dhGroup: '${pol.dhGroup}'
  pfsGroup: '${pol.pfsGroup}'
}

// Deploy:
//   export VPN_PSK='<pre-shared key>'        (PowerShell: $env:VPN_PSK = '...')
//   az deployment group create -g ${rg} --parameters ${file}
// The IKE SA lifetime is fixed at 28,800 s on Azure VPN gateways.`;

    const template = `// main.bicep: local network gateway + IPsec connection on an existing VPN gateway.
// Connection parameters mirror avm/res/network/connection 0.1.7 (names, @allowed, ranges).
import { ipsecPolicyType, trafficSelectorPolicyType } from '${typesPath}'

@description('Required. Name of the existing route-based VPN gateway (VpnGw1+ SKU).')
param vpnGatewayName string

@description('Optional. Location for all resources.')
param location string = resourceGroup().location

@description('Required. Name of the local network gateway that represents the peer.')
param localNetworkGatewayName string

@description('Required. Remote connection name.')
param name string

@description('Required. Public IP of the peer VPN device.')
param peerPublicIp string

@description('Required. Address prefixes behind the peer.')
param peerAddressPrefixes string[]

@description('Required. VPN shared key. The same value has to be specified on both sides.')
@secure()
param vpnSharedKey string

@description('Optional. Gateway connection type.')
@allowed([
  'IPsec'
])
param connectionType string = 'IPsec'

@description('Optional. The connection mode for this connection.')
@allowed([
  'Default'
  'InitiatorOnly'
  'ResponderOnly'
])
param connectionMode string = 'Default'

@description('Optional. Connection protocol used for this connection.')
@allowed([
  'IKEv1'
  'IKEv2'
])
param connectionProtocol string = 'IKEv2'

@description('Optional. The dead peer detection timeout of this connection in seconds.')
@minValue(9)
@maxValue(3600)
param dpdTimeoutSeconds int = 45

@description('Optional. Enable policy-based traffic selectors.')
param usePolicyBasedTrafficSelectors bool = false

@description('Optional. The traffic selector policies to be considered by this connection.')
param trafficSelectorPolicies trafficSelectorPolicyType[] = []

@description('Required. The custom IPsec/IKE policy for this connection.')
param customIPSecPolicy ipsecPolicyType

resource vpnGateway 'Microsoft.Network/virtualNetworkGateways@2024-05-01' existing = {
  name: vpnGatewayName
}

resource localGateway 'Microsoft.Network/localNetworkGateways@2024-05-01' = {
  name: localNetworkGatewayName
  location: location
  properties: {
    gatewayIpAddress: peerPublicIp
    localNetworkAddressSpace: {
      addressPrefixes: peerAddressPrefixes
    }
  }
}

resource connection 'Microsoft.Network/connections@2024-05-01' = {
  name: name
  location: location
  properties: {
    connectionType: connectionType
    connectionMode: connectionMode
    connectionProtocol: connectionProtocol
    dpdTimeoutSeconds: dpdTimeoutSeconds
    virtualNetworkGateway1: any({ id: vpnGateway.id })
    localNetworkGateway2: any({ id: localGateway.id })
    sharedKey: vpnSharedKey
    usePolicyBasedTrafficSelectors: usePolicyBasedTrafficSelectors
    trafficSelectorPolicies: trafficSelectorPolicies
    ipsecPolicies: [
      customIPSecPolicy
    ]
  }
}

output resourceId string = connection.id
output name string = connection.name`;

    const types = `// ${typesPath}: must export these two types (copied from avm/res/network/connection 0.1.7)
@export()
@description('The custom IPSec policy configuration for the connection.')
type ipsecPolicyType = {
  saLifeTimeSeconds: int
  saDataSizeKilobytes: int
  ipsecEncryption: ${quoteUnion(AVM.ipsecEncryption)}
  ipsecIntegrity: ${quoteUnion(AVM.ipsecIntegrity)}
  ikeEncryption: ${quoteUnion(AVM.ikeEncryption)}
  ikeIntegrity: ${quoteUnion(AVM.ikeIntegrity)}
  dhGroup: ${quoteUnion(AVM.dhGroup)}
  pfsGroup: ${quoteUnion(AVM.pfsGroup)}
}

@export()
@description('Traffic selector policy configuration.')
type trafficSelectorPolicyType = {
  localAddressRanges: string[]
  remoteAddressRanges: string[]
}`;

    return [
      { title: file, text: params },
      { title: "main.bicep (template the parameter file uses)", text: template },
      { title: `${typesPath} (required exports)`, text: types },
    ];
  }

  function checks({ S, k, add }) {
    const me = S[k];
    if (S.p1life !== 28800)
      add("warn", `Azure (site ${k}) always uses 28,800 s for the IKE SA. Lifetimes need not match, but set the peer to 28,800 to avoid rekey collisions.`);
    if (S.p2life < 300) add("err", "Azure requires a phase 2 lifetime of at least 300 s.");
    if (S.p2kb && S.p2kb < 1024) add("err", "Azure requires a phase 2 lifetime of at least 1,024 KB (or 0 for the default).");

    const raw = S.dpdInt * S.dpdRetry;
    if (raw < 9 || raw > 3600) add("err", `Azure DPD timeout must be 9–3600 s; interval × retries is ${raw} s.`);
    else if (raw < 30 || raw > 45) add("warn", `Azure DPD timeout becomes ${raw} s. Microsoft recommends 30–45 s.`);

    const tf = me.iac === "terraform";
    const types = (me.types || "").trim();
    if (tf) { /* Terraform needs no types file */ }
    else if (!types)
      add("err", `Azure (site ${k}): a Bicep types file is required. main.bicep imports ipsecPolicyType and trafficSelectorPolicyType from it.`);
    else if (!/\.bicep$/.test(types) && !/^br[:/]/.test(types))
      add("warn", `Azure (site ${k}): the types file path should point to a .bicep file (or a br: registry reference).`);

    const pol = policy(S);
    Object.keys(pol)
      .filter((f) => AVM[f])
      .forEach((f) => {
        if (!AVM[f].includes(pol[f]))
          add("err", `Azure (site ${k}): ${f} = '${pol[f]}' is not an allowed value in ${tf ? "the azurerm provider" : "the AVM connection module"}.`, "crypto");
      });

    const mode = me.cmode || "Default";
    if (!AVM.connectionMode.includes(mode))
      add("err", `Azure (site ${k}): connectionMode must be Default, InitiatorOnly or ResponderOnly.`);
    else if (mode !== "Default")
      add("info", `Azure (site ${k}) is ${mode}: ${mode === "InitiatorOnly"
        ? "Azure starts the tunnel and never answers the peer's attempts."
        : "the peer must start the tunnel; Azure only responds."}`);
  }

  function notes({ S, add }) {
    add("info", "Azure: custom IPsec/IKE policy requires VpnGw1–5/AZ (or Standard/HighPerformance). The Basic SKU does not support it.");
    if (S.A.vendor === "azure" && S.B.vendor === "azure")
      add("info", "Azure to Azure: consider a VNet-to-VNet connection instead. Both connections need the same policy.");
  }

  TM.register({
    id: "azure",
    order: 1,
    label: "Microsoft Azure VPN Gateway",
    short: "Azure",
    modes: ["route"],
    narrow: true, // usePolicyBasedTrafficSelectors
    supports: {
      p1enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm"],
      p1int: ["sha1", "sha256", "sha384", "md5"],
      dh: [2, 14, 19, 20, 24],
      p2enc: ["aes128", "aes192", "aes256", "aes128gcm", "aes256gcm", "3des"],
      p2int: ["sha1", "sha256", "md5"],
      pfs: [0, 2, 14, 19, 20, 24],
    },
    fields: {
      azure: true, // connection mode and Bicep types file
      rg: ["Resource group", ""],
      gw: ["VPN gateway name", ""],
      loc: ["Region", ""],
      iac: [["bicep", "Bicep (.bicepparam + main.bicep)"], ["terraform", "Terraform (azurerm)"]],
    },
    hint: "Azure is always route-based. Against a policy-based peer, usePolicyBasedTrafficSelectors is switched on automatically.",
    dpdTimeout,
    names: (S) => ({
      p1enc: spell(N.enc, S.p1enc),
      p1int: spell(N.int, S.p1int),
      dh: spell(N.dh, S.dh),
      p2enc: spell(N.enc, S.p2enc),
      p2int: isGcm(S.p2enc) ? spell(N.enc, S.p2enc) : spell(N.int, S.p2int),
      pfs: spell(N.pfs, S.pfs),
      dpd: `dpdTimeoutSeconds ${dpdTimeout(S)}`,
    }),
    narrowNote: "Azure: usePolicyBasedTrafficSelectors = true.",
    pdfNote: (S, eff) =>
      [`Azure VPN Gateway uses a fixed IKE SA lifetime of 28,800 s and a DPD timeout of ${dpdTimeout(S)} s (no separate retry count).`]
        .concat(eff.narrowed ? ["The Azure connection uses usePolicyBasedTrafficSelectors = true; the peer must propose every subnet pair listed."] : []),
    checks,
    notes,
    generate,
    sources: {
      status: "Verified 2026-10-19",
      used: "Allowed IKE/IPsec algorithms, DH/PFS names, GCM pairing rule, fixed 28,800 s IKE SA, DPD 9–3600 s, SKU requirement, policy-based traffic selectors. Bicep parameter names and allowed values follow the AVM connection module 0.1.7; the Terraform output uses azurerm_virtual_network_gateway_connection (azurerm 4.x) with the same inputs.",
      links: [
        ["Microsoft Learn: Configure custom IPsec/IKE connection policies", "https://learn.microsoft.com/en-us/azure/vpn-gateway/ipsec-ike-policy-howto"],
        ["Microsoft Learn: Microsoft.Network/connections (Bicep)", "https://learn.microsoft.com/en-us/azure/templates/microsoft.network/connections?pivots=deployment-language-bicep"],
        ["Terraform azurerm: azurerm_virtual_network_gateway_connection", "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_gateway_connection"],
        ["Azure Verified Modules: avm/res/network/connection", "https://github.com/Azure/bicep-registry-modules/tree/main/avm/res/network/connection"],
      ],
    },
  });
})();
