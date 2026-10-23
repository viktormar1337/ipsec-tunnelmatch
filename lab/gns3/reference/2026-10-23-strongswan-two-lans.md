# IPsec Tunnelmatch GNS3 lab: two networks per site

2026-10-23 · GNS3 2.2.61 (v2) · profile `strongest` · `--lans 2` · 6/6 pairs passed, one pair per run

Setup as in [the strongSwan 6.1 retest](2026-10-23-strongswan-6.1-retest.md): strongSwan 6.1.0 against OPNsense 26.7.7, pfSense 2.7.2, MikroTik CHR 7.24.5, VyOS rolling, OpenWrt 25.12.6 and PAN-OS 12.2.3. Every node has two local networks, 10.x.0.0/24 and 10.x.100.0/24, so each tunnel has 4 subnet pairs. The tool generated one SA per pair on every platform (strongSwan/OpenWrt children, OPNsense children, pfSense phase 2 entries, MikroTik policies, VyOS tunnels, PAN-OS proxy-IDs).

Checks per tunnel: a ping for every subnet pair in both directions (8; PAN-OS cannot ping from its LAN address with the legacy virtual router, so there only strongSwan's 4), and the number of subnet pairs with an installed child SA on every node that shows it (all but MikroTik). Every node reported 4 of 4. No generator changes were needed for multiple networks.

| | Tunnel | Profile |
|---|---|---|
| ✅ | TM-OPNSENSE ↔ TM-STRONGSWAN | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-PFSENSE ↔ TM-STRONGSWAN | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-MIKROTIK | AES-256-CBC / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-VYOS | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-OPENWRT | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |
| ✅ | TM-STRONGSWAN ↔ TM-PANOS | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20  |

### ✅ TM-OPNSENSE ↔ TM-STRONGSWAN

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-OPNSENSE 10.3.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-OPNSENSE 10.3.0.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-OPNSENSE 10.3.100.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-OPNSENSE 10.3.100.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.3.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.3.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.3.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.3.100.1: 5/5 replies
- ✅ TM-OPNSENSE: IKE SA state ESTABLISHED
- ✅ TM-OPNSENSE: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-OPNSENSE: ESP AES-GCM-256
- ✅ TM-OPNSENSE: child SAs for 4 of 4 subnet pairs
- ✅ TM-OPNSENSE: packets out 40, in 40
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: child SAs for 4 of 4 subnet pairs
- ✅ TM-STRONGSWAN: packets out 40, in 40

### ✅ TM-PFSENSE ↔ TM-STRONGSWAN

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-PFSENSE 10.5.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-PFSENSE 10.5.0.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-PFSENSE 10.5.100.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-PFSENSE 10.5.100.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.5.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.5.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.5.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.5.100.1: 5/5 replies
- ✅ TM-PFSENSE: IKE SA state ESTABLISHED
- ✅ TM-PFSENSE: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-PFSENSE: ESP AES-GCM-256
- ✅ TM-PFSENSE: child SAs for 4 of 4 subnet pairs
- ✅ TM-PFSENSE: packets out 40, in 40
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: child SAs for 4 of 4 subnet pairs
- ✅ TM-STRONGSWAN: packets out 40, in 40

### ✅ TM-STRONGSWAN ↔ TM-MIKROTIK

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.6.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.6.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.6.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.6.100.1: 5/5 replies
- ✅ Ping TM-MIKROTIK 10.6.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-MIKROTIK 10.6.0.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-MIKROTIK 10.6.100.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-MIKROTIK 10.6.100.1 → 10.4.100.1: 5/5 replies
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-CBC-256 / SHA384 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: child SAs for 4 of 4 subnet pairs
- ✅ TM-STRONGSWAN: packets out 40, in 40
- ✅ TM-MIKROTIK: IKE SA state ESTABLISHED
- ✅ TM-MIKROTIK: IKE 
- ✅ TM-MIKROTIK: ESP AES-GCM-256
- ✅ TM-MIKROTIK: packets out 2800, in 2800

### ✅ TM-STRONGSWAN ↔ TM-VYOS

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.8.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.8.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.8.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.8.100.1: 5/5 replies
- ✅ Ping TM-VYOS 10.8.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-VYOS 10.8.0.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-VYOS 10.8.100.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-VYOS 10.8.100.1 → 10.4.100.1: 5/5 replies
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: child SAs for 4 of 4 subnet pairs
- ✅ TM-STRONGSWAN: packets out 40, in 40
- ✅ TM-VYOS: IKE SA state ESTABLISHED
- ✅ TM-VYOS: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-VYOS: ESP AES-GCM-256
- ✅ TM-VYOS: child SAs for 4 of 4 subnet pairs
- ✅ TM-VYOS: packets out 40, in 40

### ✅ TM-STRONGSWAN ↔ TM-OPENWRT

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.9.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.9.100.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.9.0.1: 5/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.9.100.1: 5/5 replies
- ✅ Ping TM-OPENWRT 10.9.0.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-OPENWRT 10.9.0.1 → 10.4.100.1: 5/5 replies
- ✅ Ping TM-OPENWRT 10.9.100.1 → 10.4.0.1: 5/5 replies
- ✅ Ping TM-OPENWRT 10.9.100.1 → 10.4.100.1: 5/5 replies
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: child SAs for 4 of 4 subnet pairs
- ✅ TM-STRONGSWAN: packets out 40, in 40
- ✅ TM-OPENWRT: IKE SA state ESTABLISHED
- ✅ TM-OPENWRT: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-OPENWRT: ESP AES-GCM-256
- ✅ TM-OPENWRT: child SAs for 4 of 4 subnet pairs
- ✅ TM-OPENWRT: packets out 40, in 40

### ✅ TM-STRONGSWAN ↔ TM-PANOS

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.10.0.1: 4/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.10.100.1: 4/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.10.0.1: 4/5 replies
- ✅ Ping TM-STRONGSWAN 10.4.100.1 → 10.10.100.1: 4/5 replies
- ✅ Ping TM-PANOS 10.10.0.1 → 10.4.0.1: skipped, not possible from this device's CLI
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: child SAs for 4 of 4 subnet pairs
- ✅ TM-STRONGSWAN: packets out 16, in 16
- ✅ TM-PANOS: IKE SA state ESTABLISHED
- ✅ TM-PANOS: IKE AES-GCM-256 / 20
- ✅ TM-PANOS: ESP AES-GCM-256 / 20
- ✅ TM-PANOS: child SAs for 4 of 4 subnet pairs
- ✅ TM-PANOS: packets out 16, in 16
