# IPsec Tunnelmatch GNS3 lab

2026-10-20 20:28 · GNS3 2.2.61 (v2) · profile `strongest` · 1/1 tunnels passed

Setup: GNS3 2.2.61 server in an Ubuntu 24.04 VM on Proxmox (nested KVM), OPNsense 26.1 (nano image), strongSwan container (`lab/gns3/strongswan`, Ubuntu 24.04 packages).

| | Tunnel | Profile | Failed checks |
|---|---|---|---|
| ✅ | TM-OPNSENSE ↔ TM-STRONGSWAN | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |

## Nodes

- ✅ **TM-OPNSENSE** configured
- ✅ **TM-STRONGSWAN** configured

### ✅ TM-OPNSENSE ↔ TM-STRONGSWAN

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-OPNSENSE 10.3.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.3.0.1: 5/5 replies
- ✅ TM-OPNSENSE: IKE SA state ESTABLISHED
- ✅ TM-OPNSENSE: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-OPNSENSE: ESP AES-GCM-256
- ✅ TM-OPNSENSE: packets out 10, in 10
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: packets out 10, in 10
