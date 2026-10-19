/*
 * Microsoft Azure VPN Gateway
 * Rules: Microsoft Learn, custom IPsec/IKE connection policies (verified 2026-10-19).
 * Bicep: parameter names and allowed values follow AVM avm/res/network/connection 0.1.7.
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

  function generate(c) {
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

// Side ${c.k}: Azure VPN Gateway → ${c.peer.name} (${TM.vendor(c.peer.vendor).short})
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
      add("warn", `Azure (side ${k}) always uses 28,800 s for the IKE SA. Lifetimes need not match, but set the peer to 28,800 to avoid rekey collisions.`);
    if (S.p2life < 300) add("err", "Azure requires a phase 2 lifetime of at least 300 s.");
    if (S.p2kb && S.p2kb < 1024) add("err", "Azure requires a phase 2 lifetime of at least 1,024 KB (or 0 for the default).");

    const raw = S.dpdInt * S.dpdRetry;
    if (raw < 9 || raw > 3600) add("err", `Azure DPD timeout must be 9–3600 s; interval × retries is ${raw} s.`);
    else if (raw < 30 || raw > 45) add("warn", `Azure DPD timeout becomes ${raw} s. Microsoft recommends 30–45 s.`);

    const types = (me.types || "").trim();
    if (!types)
      add("err", `Azure (side ${k}): a Bicep types file is required. main.bicep imports ipsecPolicyType and trafficSelectorPolicyType from it.`);
    else if (!/\.bicep$/.test(types) && !/^br[:/]/.test(types))
      add("warn", `Azure (side ${k}): the types file path should point to a .bicep file (or a br: registry reference).`);

    const pol = policy(S);
    Object.keys(pol)
      .filter((f) => AVM[f])
      .forEach((f) => {
        if (!AVM[f].includes(pol[f]))
          add("err", `Azure (side ${k}): ${f} = '${pol[f]}' is not an allowed value in the AVM connection module.`, "crypto");
      });

    const mode = me.cmode || "Default";
    if (!AVM.connectionMode.includes(mode))
      add("err", `Azure (side ${k}): connectionMode must be Default, InitiatorOnly or ResponderOnly.`);
    else if (mode !== "Default")
      add("info", `Azure (side ${k}) is ${mode}: ${mode === "InitiatorOnly"
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
    fields: { azure: true },
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
      used: "Allowed IKE/IPsec algorithms, DH/PFS names, GCM pairing rule, fixed 28,800 s IKE SA, DPD 9–3600 s, SKU requirement, policy-based traffic selectors. Bicep parameter names and allowed values follow the AVM connection module 0.1.7.",
      links: [
        ["Microsoft Learn: Configure custom IPsec/IKE connection policies", "https://learn.microsoft.com/en-us/azure/vpn-gateway/ipsec-ike-policy-howto"],
        ["Microsoft Learn: Microsoft.Network/connections (Bicep)", "https://learn.microsoft.com/en-us/azure/templates/microsoft.network/connections?pivots=deployment-language-bicep"],
        ["Azure Verified Modules: avm/res/network/connection", "https://github.com/Azure/bicep-registry-modules/tree/main/avm/res/network/connection"],
      ],
    },
  });
})();
