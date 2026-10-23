# IPsec Tunnelmatch GNS3 lab

2026-10-23 19:53 · GNS3 2.2.61 (v2) · profile `strongest` · 1/1 tunnels passed

Setup: GNS3 2.2.61 server in an Ubuntu 24.04 VM on Proxmox (nested KVM), PAN-OS 12.2.3 (VM-Series, `PA-VM-KVM-12.2.3.qcow2`, unlicensed; template `PA-VM`: 16 GB RAM, 2 vCPU, QEMU option `-cpu host`, 4 virtio adapters, adapter 1 = `ethernet1/1`), strongSwan container (`lab/gns3/strongswan`, Debian forky packages, strongSwan 6.1.0).

First run on a real VM-Series. What it found:
- With the default qemu64 CPU, PAN-OS 12.2 panics at boot ("Attempted to kill init"); the template needs `-cpu host`.
- Unlicensed 12.2 needs at least 14 GB RAM, otherwise it boots into the Maintenance Recovery Tool ("VM resource failure"). The driver now stops there with the reason.
- During boot the console shows `vm login:` and `PA-HDF login:`, where admin/admin is rejected. The driver waits for `PA-VM login:` and alternates admin/admin and the lab password per attempt.
- The forced password change pads its prompt (`Confirm password   :`); the prompt patterns allow any spacing.
- **Generator bug (in the released tool):** the crypto profiles were written as `set network ike crypto-profile …`; the path is `crypto-profiles`. Fixed in `js/vendors/paloalto.js`.
- `ping source … count … host …` is rejected in 12.2 (it requires `logical-router`, which needs Advanced Routing; the generated config uses the legacy virtual router). The PAN-OS-side ping is skipped; traffic is covered by strongSwan's ping and PAN-OS's `show vpn flow` counters.

The report below is from a `--reuse` recheck of the tunnel built by the full run before it (same config), after the ping change.

| | Tunnel | Profile | Failed checks |
|---|---|---|---|
| ✅ | TM-STRONGSWAN ↔ TM-PANOS | AES-256-GCM / SHA-384 / group 20 · ESP AES-256-GCM · PFS 20 | — |

## Nodes

- ✅ **TM-STRONGSWAN** configured
- ✅ **TM-PANOS** configured

### ✅ TM-STRONGSWAN ↔ TM-PANOS

- ✅ Tool reports no crypto errors for this pair
- ✅ Ping TM-STRONGSWAN 10.4.0.1 → 10.10.0.1: 5/5 replies
- ✅ Ping TM-PANOS 10.10.0.1 → 10.4.0.1: skipped, not possible from this device's CLI
- ✅ TM-STRONGSWAN: IKE SA state ESTABLISHED
- ✅ TM-STRONGSWAN: IKE AES-GCM-256 / SHA384 / 20
- ✅ TM-STRONGSWAN: ESP AES-GCM-256
- ✅ TM-STRONGSWAN: packets out 9, in 9
- ✅ TM-PANOS: IKE SA state ESTABLISHED
- ✅ TM-PANOS: IKE AES-GCM-256 / 20
- ✅ TM-PANOS: ESP AES-GCM-256 / 20
- ✅ TM-PANOS: packets out 9, in 9
