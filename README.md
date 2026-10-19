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

Open `index.html` in a browser, or publish it with GitHub Pages. No build step: it also runs straight from a local folder. The PDF export loads jsPDF and jsPDF-AutoTable from cdnjs.

## Project layout

```
index.html              page structure only
css/style.css           all styling (colour tokens, light and dark)
js/core.js              algorithm catalog, network helpers, vendor registry
js/vendors/<vendor>.js  one file per platform: supported values, spelling, checks, config generator, sources
js/analyze.js           generic checks and route-based / policy-based reconciliation
js/pdf.js               PDF parameter sheet
js/app.js               form state, rendering and wiring
```

Scripts are plain (not ES modules) so the page works from `file://`. They share one global, `TM`, and must load in the order listed in `index.html`: core, vendors, analyze, pdf, app.

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
