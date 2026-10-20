# Lab: verify generated configs with real tunnels

The lab brings up real IKEv2 tunnels with the configuration the tool generates, then checks what was actually negotiated. It runs locally in a few minutes and on every push through GitHub Actions.

## What it does

For each scenario the lab creates two Linux network namespaces, "site A" (203.0.113.10) and "site B" (198.51.100.20), joined by a virtual cable. It starts a strongSwan daemon in each, loads the `swanctl.conf` the tool generates for both sides, and checks:

1. both configs load
2. the IKE SA and every child SA come up
3. the negotiated IKE and ESP algorithms are exactly the ones the tool generated
4. traffic flows between every local subnet on A and every local subnet on B
5. a child SA rekey works and uses the PFS group
6. the tool's own checks agree with the outcome

Scenarios (`lab/scenarios.js`):

- **Baseline profiles**: recommended (AES-256-GCM, SHA-384, group 20), minimum (AES-256-CBC, SHA-256, group 14) and group 19.
- **Strongest common profile for every platform pair**, as picked by the tool's "Use strongest profile" button, grouped by identical profile.
- **Platform emulation**: PAN-OS ↔ Azure with IKE GCM. PAN-OS derives the IKE PRF from the DH group, so the lab sends what PAN-OS would send. With group 20 it must work; with group 19 it must fail, matching the error the tool shows.
- **Negative controls**: a DH group mismatch and an ESP mismatch that must fail, proving the lab catches mismatches.

## What it does not cover

Only strongSwan runs here, so the lab verifies the crypto profiles, the reconciliation logic and the strongSwan output. It does not verify the CLI syntax for PAN-OS, FortiGate, Juniper, Cisco, Meraki or Azure; those need the real platforms (see "Vendor images" below). Route-based (VTI/XFRM interface) mode and DPD timing are not tested.

## Run it locally

Linux with root (network namespaces need it):

```sh
sudo apt-get install strongswan-swanctl charon-systemd libcharon-extra-plugins libstrongswan-extra-plugins iproute2
sudo node lab/run.js            # all scenarios
sudo node lab/run.js --only pan # scenarios whose name contains "pan"
sudo node lab/run.js --keep     # leave namespaces and logs in place for inspection
sudo node lab/run.js --kernel   # use the kernel's IPsec (XFRM) instead of userspace ESP
```

ESP runs in userspace (strongSwan's `kernel-libipsec`) by default, so results don't depend on which crypto modules the host kernel has. The report is written to `lab/results/latest.md` and `latest.json`.

The lab only touches the two namespaces it creates (`tml<pid>a` and `tml<pid>b`) and the daemons it starts; it does not stop or change a strongSwan already running on the host.

## Vendor images

To test the vendor syntax as well, the same idea works with real virtual appliances, for example in containerlab or on Proxmox: Juniper vSRX, Cisco Catalyst 8000v or ASAv, FortiGate-VM, Palo Alto VM-Series and OPNsense. These need your own images and licences, so they are not part of the automated lab.
