# IPsec Tunnelmatch GNS3 lab

2026-10-21 17:55 · GNS3 2.2.61 (v2) · profile `strongest` · 1/1 tunnels passed

Setup: GNS3 2.2.61 server in an Ubuntu 24.04 VM on Proxmox (nested KVM), pfSense CE 2.7.2 (installed once from the ISO, serial console on, template `pfSense 2.7.2 (tmlab)` made with `prepare_template.py`), strongSwan container (`lab/gns3/strongswan`, Ubuntu 24.04 packages).

The first runs stopped at the console login: pfSense's shell runs `resizewin` before every prompt, which asks the terminal for its size (`ESC[6n`) and, without an answer, reads what is typed next as the reply. The console client now answers the query like an 80x25 terminal, keeps escape sequences that are split across reads together, and waits for the console to go quiet before starting `/bin/sh`.

| | Tunnel | Profile | Failed checks |
|---|---|---|---|
| ✅ | TM-PFSENSE ↔ TM-STRONGSWAN | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |

## Nodes

- ✅ **TM-PFSENSE** configured
- ✅ **TM-STRONGSWAN** configured

### ✅ TM-PFSENSE ↔ TM-STRONGSWAN

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-PFSENSE 10.5.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.5.0.1: 5/5 replies
- ✅ TM-PFSENSE: IKE SA state ESTABLISHED
- ✅ TM-PFSENSE: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-PFSENSE: ESP AES-GCM-256
- ✅ TM-PFSENSE: packets out 10, in 10
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: packets out 10, in 10
