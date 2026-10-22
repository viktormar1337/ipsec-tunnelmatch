# IPsec Tunnelmatch GNS3 lab

2026-10-21 · GNS3 2.2.61 (v2) · profile `strongest`

Setup: GNS3 2.2.61 server in an Ubuntu 24.04 VM on Proxmox (nested KVM), templates from `add_templates.py`: MikroTik CHR 7.24.5, VyOS rolling 2026.10.21-0025 (live ISO), OpenWrt 25.12.6 with strongSwan 6.0.7 (`OpenWrt (tmlab)`), and the strongSwan container (`lab/gns3/strongswan`, Ubuntu 24.04 packages, strongSwan 5.9.13).

Only the summary of each run was kept (the per-check details in `results/latest.md` are overwritten by the next run).

**Not yet in the tool:** these runs used generator changes that are not released yet, so a run from this commit generates different configs for these platforms:

- MikroTik: `auth-algorithms=""` with AES-GCM in phase 2. RouterOS 7.24.5 rejects `auth-algorithms=null` ("AEAD already provides authentication"), and leaving the option out fails the same way.
- OpenWrt: `kmod-crypto-seqiv` is needed for AES-GCM in ESP (the template has it); without it the kernel refuses the ESP SA ("unable to initialize cryptographic operations").
- OpenWrt: the legacy `ipsec` service that `strongswan-full` enables must be stopped and disabled, and leftover `charon` / `swanctl --load-all` processes killed, before `swanctl` restarts; otherwise a leftover process can hold UDP 500/4500. The lab's own OpenWrt merge in `generate.js` already does this.
- VyOS and strongSwan: `close-action start` (VyOS ike-group) / `close_action = start`, so they re-initiate when OpenWrt deletes both IKE SAs after both ends initiated at once.

## Full mesh, 18:48 (MikroTik fix and seqiv; before the OpenWrt service cleanup and close-action)

| | Tunnel | Profile | Failed checks |
|---|---|---|---|
| ✅ | TM-STRONGSWAN ↔ TM-MIKROTIK | AES-256-CBC / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |
| ✅ | TM-STRONGSWAN ↔ TM-VYOS | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |
| ✅ | TM-STRONGSWAN ↔ TM-OPENWRT | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |
| ✅ | TM-MIKROTIK ↔ TM-VYOS | AES-256-CBC / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |
| ✅ | TM-MIKROTIK ↔ TM-OPENWRT | AES-256-CBC / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |
| ✅ | TM-VYOS ↔ TM-OPENWRT | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |

A second mesh run at 20:18 passed 5 of 6; VyOS ↔ OpenWrt had no IKE SA (both ends initiated, OpenWrt deleted both IKE SAs, nothing re-initiated), which led to the close-action change. The OpenWrt pairs were then run again with all changes above.

## TM-STRONGSWAN ↔ TM-OPENWRT, 20:51 (all changes)

| | Tunnel | Profile | Failed checks |
|---|---|---|---|
| ✅ | TM-STRONGSWAN ↔ TM-OPENWRT | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |

## TM-VYOS ↔ TM-OPENWRT, 20:53 (all changes)

| | Tunnel | Profile | Failed checks |
|---|---|---|---|
| ✅ | TM-VYOS ↔ TM-OPENWRT | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |

Between these runs, OpenWrt's IKE SA was terminated by hand (`swanctl --terminate`), once with VyOS and once with strongSwan as the peer; both re-initiated at once and the child SA was installed again.
