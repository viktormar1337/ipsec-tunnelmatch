# IPsec Tunnelmatch GNS3 lab: strongSwan 6.1 retest

2026-10-23 · GNS3 2.2.61 (v2) · profile `strongest` · 6/6 pairs passed, one pair per run

Setup: GNS3 2.2.61 server in an Ubuntu 24.04 VM on Proxmox (nested KVM). strongSwan container rebuilt from Debian forky (`lab/gns3/strongswan/Dockerfile`), strongSwan 6.1.0; the earlier passes ran with Ubuntu 24.04's 5.9.13. Peers: OPNsense 26.7.7 (`OPNsense 26.7 (tmlab)`), pfSense 2.7.2 (`pfSense 2.7.2 (tmlab)`), MikroTik CHR 7.24.5, VyOS rolling (live ISO), OpenWrt 25.12.6 (`OpenWrt (tmlab)`), and PAN-OS 12.2.3 ([its own report](2026-10-23-panos-strongswan.md)). Generators as in the working tree on that day, including the unreleased MikroTik, OpenWrt, VyOS and strongSwan changes and the PAN-OS `crypto-profiles` fix.

| | Tunnel | Profile |
|---|---|---|
| ✅ | TM-OPNSENSE ↔ TM-STRONGSWAN | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-PFSENSE ↔ TM-STRONGSWAN | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-MIKROTIK | AES-256-CBC / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-VYOS | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-OPENWRT | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-PANOS | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 |

With VyOS, both ends initiate and strongSwan 6.1 keeps both IKE SAs ESTABLISHED (5.9.13 still had the second one in CONNECTING), each with its own child SA; traffic uses one of them. The first VyOS run failed only because the swanctl parser picked the idle duplicate ("packets out 0, in 0") while both pings had 5/5 replies. The parser now prefers the established SA with traffic (selftest case `SWANCTL_TWO_ESTABLISHED`); the rerun passed. The duplicate IKE SA itself is harmless, but the generators could avoid it by letting only one side initiate.

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

### ✅ TM-STRONGSWAN ↔ TM-MIKROTIK

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.6.0.1: 5/5 replies
- ✅ Ping TM-MIKROTIK 10.6.0.1 → 10.4.0.1: 5/5 replies
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-CBC-256 / SHA384 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: packets out 10, in 10
- ✅ TM-MIKROTIK: IKE SA state ESTABLISHED
- ✅ TM-MIKROTIK: IKE 
- ✅ TM-MIKROTIK: ESP AES-GCM-256
- ✅ TM-MIKROTIK: packets out 700, in 700

### ✅ TM-STRONGSWAN ↔ TM-VYOS

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.8.0.1: 5/5 replies
- ✅ Ping TM-VYOS 10.8.0.1 → 10.4.0.1: 5/5 replies
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: packets out 10, in 10
- ✅ TM-VYOS: IKE SA state ESTABLISHED
- ✅ TM-VYOS: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-VYOS: ESP AES-GCM-256
- ✅ TM-VYOS: packets out 10, in 10

### ✅ TM-STRONGSWAN ↔ TM-OPENWRT

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.9.0.1: 5/5 replies
- ✅ Ping TM-OPENWRT 10.9.0.1 → 10.4.0.1: 5/5 replies
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: packets out 10, in 10
- ✅ TM-OPENWRT: IKE SA state ESTABLISHED
- ✅ TM-OPENWRT: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-OPENWRT: ESP AES-GCM-256
- ✅ TM-OPENWRT: packets out 10, in 10
