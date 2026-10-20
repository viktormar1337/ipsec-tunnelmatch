# IPsec Tunnelmatch

[![Lab](https://github.com/viktormar1337/ipsec-tunnelmatch/actions/workflows/lab.yml/badge.svg)](https://github.com/viktormar1337/ipsec-tunnelmatch/actions/workflows/lab.yml)

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
| Juniper SRX (Junos) | `set` commands (st0, traffic selectors) | Verified |
| strongSwan | `swanctl.conf` | Syntax reference |
| OPNsense / pfSense | Connections fields / Tunnels fields | Syntax reference (OPNsense proposal list checked against its source) |

"Verified" means the supported algorithms and limits were checked against the vendor's own documentation (2026-10-19; Juniper 2026-10-20). "Syntax reference" means commands and field names follow vendor docs, but the algorithm lists have not yet been checked against a version-specific table. All sources are listed in the Sources section of the page.

IKEv2 only: every supported platform does IKEv2.

## Recommended baseline and checklist

The **Recommended baseline** panel grades the chosen profile against NIST SP 800-77 Rev. 1, RFC 8247, NSA and BSI TR-02102-3 guidance:

| Setting | Recommended | Minimum |
|---|---|---|
| IKE version | IKEv2 only | IKEv2 only |
| Phase 1 encryption | AES-256 (GCM or CBC) | AES-128 |
| Integrity / PRF | SHA-384 or SHA-512 | SHA-256 |
| DH group | 19, 20 or 21 | 14 (never 1, 2, 5 or 24) |
| Phase 2 encryption | AES-256-GCM | AES-128 / AES-CBC |
| PFS | On, as strong as phase 1 | On |
| Lifetimes | IKE SA ≤ 24 h, child SA ≤ 8 h | same |

**Use strongest profile both sides support** tries every combination and picks the best one without algorithm errors, avoiding values that depend on firmware version when possible. PAN-OS ↔ Azure, for example, gets AES-256-GCM / SHA-384 / group 20; anything with a Meraki MX gets AES-256-CBC / SHA-256 / group 14.

The **Go-live checklist** covers the things the tool cannot check (key quality, removed default proposals, restricted ports, verified SAs, rekey and failover tests). Ticks are kept in the browser and printed in the PDF.

## Working configurations

Got a tunnel running? Use **Report a working configuration** in the tool: it opens the [Working configuration](https://github.com/viktormar1337/ipsec-tunnelmatch/issues/new?template=working_config.yml) form with platforms and settings filled in, and you add the OS/firmware versions. Confirmed combinations are collected in [#1 Verified working configurations](https://github.com/viktormar1337/ipsec-tunnelmatch/issues/1).

## Lab

[`lab/`](lab/README.md) brings up real IKEv2 tunnels between two network namespaces with the configs the tool generates, and checks the negotiated algorithms, traffic, rekey and PFS. It covers the baseline profiles, the strongest common profile for every platform pair, a PAN-OS ↔ Azure emulation and negative controls. It runs on every push through GitHub Actions, or locally with `sudo node lab/run.js`. Vendor CLI syntax is not tested there.

[`lab/gns3/`](lab/gns3/README.md) runs the generated configs on real appliances in GNS3 (Catalyst 8000v, ASAv, OPNsense and strongSwan, full mesh, strongest common profile per pair) and checks SAs, algorithms and traffic for every tunnel. It needs your own GNS3 server and images.

## Azure Bicep

The Azure output imports `ipsecPolicyType` and `trafficSelectorPolicyType` from a types file you provide (default `./types.bicep`). The page shows the exports that file needs. The shared key is read with `readEnvironmentVariable('VPN_PSK')` at deploy time.

## Use

Open `index.html` in a browser, or publish it with GitHub Pages. No build step: it also runs straight from a local folder. The PDF export loads jsPDF and jsPDF-AutoTable from cdnjs.

## Project layout

```
index.html              page structure only
css/style.css           all styling (colour tokens, light and dark)
js/core.js              algorithm catalog, network helpers, vendor registry
js/vendors/<vendor>.js  one file per platform: supported values, spelling, checks, config generator, sources
js/analyze.js           generic checks and route-based / policy-based reconciliation
js/baseline.js          recommended baseline, strongest common profile, go-live checklist
js/pdf.js               PDF parameter sheet
js/app.js               form state, rendering and wiring
lab/                    real-tunnel tests (strongSwan in network namespaces)
lab/gns3/               the same on real appliances in GNS3
```

Scripts are plain (not ES modules) so the page works from `file://`. They share one global, `TM`, and must load in the order listed in `index.html`: core, vendors, analyze, baseline, pdf, app.

### Adding or changing a vendor

Everything about a platform lives in its own file under `js/vendors/`. A vendor registers itself with `TM.register({...})`:

| Field | Purpose |
|---|---|
| `id`, `order`, `label`, `short` | Identity and position in the platform list |
| `modes` | `["route"]`, `["policy"]` or both; the first is the default |
| `narrow` | `true` if a route-based tunnel can narrow its selectors to subnet pairs |
| `supports` | Allowed values for `p1enc`, `p1int`, `dh`, `p2enc`, `p2int`, `pfs` (neutral ids from `core.js`) |
| `verify`, `verifyNote` | Values that work only on some versions, with the warning to show |
| `fields`, `defaults` | Which endpoint fields to show (with labels) and their default values |
| `names(S)` | How the platform spells each chosen value (name mapping tab and PDF) |
| `checks(ctx)`, `notes(ctx)` | Platform rules per side, and notes shown once per platform |
| `generate(c)` | Returns the config as a string, or a list of `{ title, text }` blocks |
| `sources` | Status, what was taken from the docs, and links (Sources section) |

Add the new file to the script list in `index.html`, after `core.js`.

Generated configuration is a starting point. Lab-test before production.
