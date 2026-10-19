# IPsec Tunnelmatch

A single-page tool for matching IPsec site-to-site settings between two different vendors.

Describe both endpoints and one shared crypto profile. The tool:

- checks that both platforms support every algorithm, DH/PFS group and lifetime you pick
- reconciles route-based (VTI) and policy-based peers, narrowing traffic selectors where needed
- generates configuration for each side
- produces a parameter sheet as PDF to send to the other party

Everything runs in the browser. Nothing is sent anywhere, and the pre-shared key is never entered: it is agreed out-of-band and every config shows `<PSK>` where it goes.

## Platforms

| Platform | Output | Status |
|---|---|---|
| Microsoft Azure VPN Gateway | `.bicepparam` + `main.bicep` (AVM `network/connection` 0.1.7 parameter names) | Verified |
| Palo Alto Networks PAN-OS | `set` commands | Verified |
| Cisco Meraki MX | Dashboard field values | Verified |
| Fortinet FortiGate | FortiOS CLI | Syntax reference |
| Cisco IOS-XE | CLI (VTI or crypto map) | Syntax reference |
| Cisco ASA | CLI (VTI or crypto map) | Syntax reference |
| strongSwan | `swanctl.conf` | Syntax reference |
| OPNsense / pfSense | Connections fields / Tunnels fields | Syntax reference |

"Verified" means the supported algorithms and limits were checked against the vendor's own documentation (2026-10-19). "Syntax reference" means commands and field names follow vendor docs, but the algorithm lists have not yet been checked against a version-specific table. All sources are listed in the Sources section of the page.

IKEv2 only: every supported platform does IKEv2.

## Azure Bicep

The Azure output imports `ipsecPolicyType` and `trafficSelectorPolicyType` from a types file you provide (default `./types.bicep`). The page shows the exports that file needs. The shared key is read with `readEnvironmentVariable('VPN_PSK')` at deploy time.

## Use

Open `index.html` in a browser, or publish it with GitHub Pages. The PDF export loads jsPDF and jsPDF-AutoTable from cdnjs.

Generated configuration is a starting point. Lab-test before production.
