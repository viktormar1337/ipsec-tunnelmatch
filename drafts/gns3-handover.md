<!-- Temporary handover between Claude Code sessions. Delete drafts/ once the move is done. -->
# Handover: moving the GNS3 lab to the new lab setup

From the Claude Code session on the old GNS3 server (Ubuntu 24.04 VM on Proxmox, GNS3 2.2.61,
server runs as root) to the session on Viktor's new lab setup. Written 2026-10-26 at commit
`5bc8f96` plus this file.

## Start here

1. `git pull` in the repo, then read `CLAUDE.md` (rules, node addressing, status) and
   `lab/gns3/README.md` (templates, drivers, preparation steps). Both are current.
2. Rules that matter most: the pre-shared key never goes into any committed file; IKEv2 only;
   the UI says "Site A" / "Site B"; **commit and push only when Viktor asks**.
3. Working preference: run the GNS3 lab **two nodes per run** (`--nodes a,b`), not the full mesh.
4. Nothing secret is in this file. The old `lab/gns3/lab.json` (server URL and credentials, lab
   password) is git-ignored; copy it with scp or write a new one from `lab.example.json`.

## What the lab is

`lab/gns3/run.py` builds a GNS3 project, pushes the configs the web tool generates
(`lab/gns3/generate.js`) over the node consoles, and checks every tunnel: IKE/child SA state,
negotiated algorithms against the plan, pings both ways, packet counters. Results go to
`lab/gns3/results/latest.md` plus one console log per node. Reports of past runs are in
`lab/gns3/reference/`.

```sh
python3 lab/gns3/selftest.py --parsers-only        # no root needed
python3 lab/gns3/run.py --dry-run                  # plan + server + templates
python3 lab/gns3/run.py --nodes strongswan,panos --keep
python3 lab/gns3/run.py --nodes vyos,mikrotik --lans 2      # 2 networks per site (4 subnet pairs)
python3 lab/gns3/run.py --nodes strongswan,mikrotik --rekey 300   # 15 min rekey soak
```

`--reuse` skips the build **and the config push**; after any generator or driver change, run
without it.

## Server requirements

- GNS3 server 2.2.x with KVM (nested KVM if it is a VM; PAN-OS needs `-cpu host`).
- RAM: PA-VM alone needs 16 GB (12.2 unlicensed refuses to start below 14 GB). The old VM had
  122 GB / 8 vCPU; two-node runs need far less.
- Docker on the GNS3 server, for the strongSwan node; the user running the lab in the `docker` group.
- Node.js (for `generate.js`) and Python 3.9+ on the machine that runs `run.py`. `qemu-img` where
  `prepare_template.py` runs.
- The VPCS template (built into GNS3) and the built-in Ethernet switch.

## Images to copy (scp)

On the old server they are in `/root/GNS3/images/QEMU/` (root only). All prepared "(tmlab)" disks
are standalone qcow2 (flattened by `prepare_template.py`), so a plain copy works. Put them in the
new server's images folder or upload them through the GNS3 API / GUI.

| File | Template on the old server | Notes |
|---|---|---|
| `PA-VM-KVM-12.2.3.qcow2` | **PA-VM**: qemu, 16384 MB, 2 vCPU, 5 adapters virtio-net-pci, options `-cpu host`, telnet, boot c | Viktor's own image (Palo Alto support portal). Adapter 0 mgmt, 1 = ethernet1/1 WAN, 2-4 = ethernet1/2-1/4 LANs (one VPCS host each) |
| `chr-7.24.5.img` | **MikroTik CHR**: 384 MB, 1 vCPU, 4 adapters virtio, telnet | Free; `add_templates.py` can download it again |
| `vyos-2026.10.22-0026-rolling-generic-amd64.iso` | **VyOS**: 2048 MB, 2 vCPU, 3 adapters virtio, cdrom = ISO, boot d (live system) | Rolling; `add_templates.py` fetches the newest |
| `openwrt-tmlab.qcow2` | **OpenWrt (tmlab)**: 256 MB, 1 vCPU, 2 adapters virtio, telnet | Prepared (strongSwan installed). Base: `openwrt-25.12.6-x86-64-generic-ext4-combined.img` |
| `opnsense-26-7-tmlab.qcow2` | **OPNsense 26.7 (tmlab)**: 2048 MB, 1 vCPU, 4 adapters virtio, telnet | Prepared (fully updated). Base: `OPNsense-26.7-nano-amd64.img` |
| `pfsense-2-7-2-tmlab.qcow2` | **pfSense 2.7.2 (tmlab)**: 2048 MB, 1 vCPU, 6 adapters e1000, telnet | Prepared (installed from ISO). Base ISO: `pfSense-CE-2.7.2-RELEASE-amd64.iso` |

Not needed: `OPNsense-26.1-nano-amd64.img` and the plain "OPNsense 26.1" template (old run),
`vyos-2026.10.21-…iso` (superseded), the `empty*.qcow2` / `OVMF*` / `config.img` files.

Fallback if scp is not ready: the old server's API serves images,
`GET /v2/compute/qemu/images/<file>` (see `Gns3.download` in `run.py`, used by
`prepare_template.py`).

Rebuilding instead of copying: `python3 lab/gns3/add_templates.py` downloads CHR, VyOS, OpenWrt and
OPNsense, creates the templates and prepares the "(tmlab)" ones. pfSense needs the one-time install
in `lab/gns3/README.md` ("pfSense one-time preparation") and `prepare_pfsense.py`.

## strongSwan node

Not an image file: build it on the new GNS3 server.

```sh
docker build -t tunnelmatch-strongswan:latest lab/gns3/strongswan   # Debian forky, strongSwan 6.1.0
```

`run.py` creates the GNS3 docker template "tunnelmatch-strongswan" itself if it is missing, and
uses the node's auxiliary console (the main docker console gave no prompt on GNS3 2.2.61).

## lab.json

Copy `lab/gns3/lab.example.json` to `lab/gns3/lab.json` and set `server.url`, `server.user`,
`server.password` and the lab `password`. Template names must match the new server's templates
(the old lab.json used `"OPNsense 26.7 (tmlab)"`; `run.py` also accepts a unique
`"<name> <version>"` match). Nodes missing from lab.json (for example `panos`) are taken from
`lab.example.json` and enabled only when named in `--nodes`.

## Verify the move

1. `python3 lab/gns3/selftest.py --parsers-only`, then `sudo python3 lab/gns3/selftest.py`
   (live part, needs root and strongSwan installed locally; CI also runs it).
2. `python3 lab/gns3/run.py --dry-run` (server and templates found).
3. Pairs that passed on the old server, as a baseline:
   `--nodes strongswan,opnsense`, `strongswan,pfsense`, `strongswan,mikrotik`, `strongswan,vyos`,
   `strongswan,openwrt`, `strongswan,panos`, `panos,mikrotik`, `vyos,mikrotik --lans 2`.

## State at handover

- All six real platforms pass against strongSwan 6.1.0, also with `--lans 2`; PAN-OS also with
  `--lans 3` (9 subnet pairs). Rekey soaks strongSwan ↔ MikroTik and strongSwan ↔ PAN-OS pass.
- Generator fixes found by the lab and released: PAN-OS `crypto-profiles` path and NAT-T on the
  gateway; MikroTik `my-id=auto` (RouterOS as responder rejected PAN-OS, which sends no IDr; root
  cause proven from a capture, see `lab/gns3/reference/2026-10-24-cross-vendor-and-rekey.md`).
- vSRX, IOS-XE and ASA drivers are tested only against simulated consoles; there were no images
  on the old server. Expect small prompt/format fixes on the first real run.
- AWS and Google Cloud support were added to the web tool (`js/vendors/aws.js`, `gcp.js`,
  CLI/gcloud scripts and Terraform, `terraform validate` clean); not tested on real accounts.

## Open items

- Post `drafts/issue-2-comment.md` on issue #2 (asks for testers with AWS/GCP accounts):
  `gh issue comment 2 --repo viktormar1337/ipsec-tunnelmatch --body-file drafts/issue-2-comment.md`.
- Update the pinned issue #1 table: add PAN-OS 12.2.3, the strongSwan 6.1 retest, two networks,
  the cross-vendor pairs and rekey soaks; footnote ¹ is outdated (those fixes were released
  2026-10-23).
- Real cloud tests (Azure, AWS, GCP) against a strongSwan peer, once Viktor has subscriptions.
  The on-prem side needs UDP 500/4500 forwarded and its IKE ID set to the public IP.
- Network isolation was planned for the old Proxmox host (OPNsense VM, lab network
  10.99.0.0/24, WireGuard for access); it was waiting for Viktor's details and may not apply to
  the new setup. Ask before doing anything there.
- Performance testing (iperf3 behind each side, MTU sweep): Viktor said "not today"; not started.
- Delete `drafts/` when done.

## Debug tools (drafts/tools)

From the MikroTik ↔ PAN-OS investigation; stdlib + `cryptography`, run with `python3 -I`:

- `ikedump.py <pcap> [-v]`: lists IKEv2 messages and payloads from a capture (GNS3 link capture:
  `POST /v2/projects/<p>/links/<l>/start_capture`, download via
  `/v2/projects/<p>/files/project-files/captures/<file>`).
- `ikeauth.py <pcap> <g^ir hex> <psk file> [initiator ip]`: derives the IKE keys (AES-CBC-256,
  SHA-384 profile), checks the IKE_AUTH ICV and recomputes the PSK AUTH value per RFC 7296.
  RouterOS's `ipsec` debug log prints the DH shared secret.

Useful device tricks: RouterOS `/system logging add topics=ipsec,!packet`; PAN-OS 12.2 IKE debug
is in `mp-log ikemgr-ng.log` (`debug ike global on debug`), not `ikemgr.log`.
