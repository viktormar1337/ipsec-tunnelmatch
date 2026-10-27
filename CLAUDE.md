# IPsec Tunnelmatch

A static web tool (index.html + js/) that matches IPsec site-to-site parameters between
two platforms and generates each side's config. No build step. Live at
https://viktormar1337.github.io/ipsec-tunnelmatch/.

## Layout

- `js/core.js`, `js/analyze.js`, `js/baseline.js`, `js/app.js`, `js/pdf.js`: the tool.
- `js/vendors/<id>.js`: one file per platform, registered with `TM.register({...})`
  (supports, names, checks, notes, generate, sources). Script order is in index.html.
- `lab/run.js`: strongSwan namespace lab (CI). `sudo node lab/run.js [--only <text>]`.
- `lab/gns3/`: GNS3 lab on real appliances. Read `lab/gns3/README.md` first.

## Rules

- The pre-shared key is never part of the form or any committed file. Generated configs
  show `<PSK>`; the GNS3 lab makes a random key per run and writes it only to `lab/gns3/out/`.
- IKEv2 only.
- The UI uses "Site A" / "Site B".
- Commit and push only when Viktor asks.

## GNS3 lab

Since 2026-10-27 the lab runs against a separate GNS3 server: GNS3 3.0.6 (API v3 with logins),
Ubuntu 24.04 VM on Proxmox with nested KVM, server running as its own user, Docker for the
strongSwan node. `run.py` runs on another machine and reaches the server and the node consoles
over the network. Server URL and login are in `lab/gns3/lab.json` (copied from
`lab.example.json`, git-ignored); the lab uses a dedicated GNS3 account with the Administrator
role (it creates templates and uploads images). Work two nodes per run (`--nodes a,b`).

```sh
git pull
python3 lab/gns3/selftest.py --parsers-only        # quick sanity check
python3 lab/gns3/run.py --dry-run                 # plan + check server and templates
python3 lab/gns3/run.py --nodes strongswan,opnsense --keep
```

On the GNS3 server: `docker build -t tunnelmatch-strongswan:latest lab/gns3/strongswan`.
Templates there: MikroTik CHR, VyOS, OpenWrt (tmlab), OPNsense 26.7 (tmlab) (from
`add_templates.py`) and tunnelmatch-strongswan (created by `run.py`). PA-VM and pfSense 2.7.2
(tmlab) are not there yet (the images are on the old server).

GNS3 3.x notes: node names may not contain spaces or parentheses (prepared templates get a
`default_name_format` with letters and digits only); the controller API has no image download,
so `prepare_template.py` takes the base image from `add_templates.py`'s download cache
(`~/.cache/tunnelmatch-gns3`). Run `prepare_template.py` with `TMPDIR` on a disk with a few GB
free when `/tmp` is a small tmpfs.

Node addressing (WAN 203.0.113.x, LAN 10.x.0.0/24): iosxe .11 / 10.1, asa .12 / 10.2,
opnsense .13 / 10.3, strongswan .14 / 10.4, pfsense .15 / 10.5, mikrotik .16 / 10.6,
vsrx .17 / 10.7, vyos .18 / 10.8, openwrt .19 / 10.9, panos .20 / 10.10.

Status:
- OPNsense 26.1 <-> strongSwan: passed on real images 2026-10-20
  (`lab/gns3/reference/2026-10-20-opnsense-strongswan.md`).
- pfSense 2.7.2 <-> strongSwan: passed on real images 2026-10-21
  (`lab/gns3/reference/2026-10-21-pfsense-strongswan.md`).
- strongSwan, MikroTik CHR 7.24.5, VyOS rolling, OpenWrt 25.12.6: full mesh passed 2026-10-21
  (`lab/gns3/reference/2026-10-21-strongswan-mikrotik-vyos-openwrt.md`), with generator changes
  for MikroTik, OpenWrt, VyOS and strongSwan (see that report), released 2026-10-23.
- OPNsense 26.7.7 <-> strongSwan: passed 2026-10-22
  (`lab/gns3/reference/2026-10-22-opnsense-26.7-strongswan.md`).
- Templates for MikroTik, VyOS, OpenWrt and OPNsense: `python3 lab/gns3/add_templates.py`.
- PAN-OS 12.2.3 (VM-Series, unlicensed) <-> strongSwan 6.1.0: passed 2026-10-23
  (`lab/gns3/reference/2026-10-23-panos-strongswan.md`), with a fix to the PAN-OS generator
  (`crypto-profiles` path), released 2026-10-23. Template "PA-VM" from the user's own qcow2
  (16 GB RAM, 2 vCPU, QEMU option `-cpu host`, 5 adapters: 1 = ethernet1/1 WAN, 2-4 =
  ethernet1/2-1/4 LANs, each with a VPCS host that does the PAN-OS-side pings).
- The strongSwan image is built from Debian forky (strongSwan 6.1.0). OPNsense, pfSense, MikroTik,
  VyOS, OpenWrt and PAN-OS each passed against it 2026-10-23
  (`lab/gns3/reference/2026-10-23-strongswan-6.1-retest.md`).
- Two networks per site (`--lans 2`, 4 subnet pairs per tunnel): strongSwan 6.1.0 against all six
  passed 2026-10-23 (`lab/gns3/reference/2026-10-23-strongswan-two-lans.md`).
- Cross-vendor and rekey (2026-10-24, `lab/gns3/reference/2026-10-24-cross-vendor-and-rekey.md`):
  PAN-OS <-> MikroTik passed after a PAN-OS generator fix (NAT-T on the gateway) and a MikroTik
  one (`my-id=auto`: RouterOS as responder rejected PAN-OS, which sends no IDr; solved 2026-10-26). VyOS <-> MikroTik `--lans 2` passed. Rekey soak
  (`--rekey 300`) strongSwan <-> MikroTik and strongSwan <-> PAN-OS passed.
- New server (GNS3 3.0.6), 2026-10-26: strongSwan 6.1.0 <-> MikroTik CHR 7.25, VyOS rolling
  2026.10.26, OpenWrt 25.12.6 and OPNsense 26.7.7 passed, and VyOS <-> MikroTik `--lans 2`.
  Needed for 3.x: `add_templates.py` sends `platform: x86_64` and a JSON body on node start/stop,
  `prepare_template.py` changes above. On this server both ends initiate at the same moment, so
  OPNsense <-> strongSwan ends with two ESTABLISHED IKE SAs, each end sending on its own child SA
  and receiving on the peer's; `parse_swanctl_raw` now sums the counters over the established
  IKE SAs toward the peer (selftest case `SWANCTL_SPLIT`). Still to rerun here: pfSense, PAN-OS.
- vSRX, IOS-XE, ASA: drivers tested only against simulated consoles; no templates on the
  server yet. Expect small fixes (prompts, show-command formats) on the first real run.

When a run fails: read `lab/gns3/results/latest.md` and the per-node console logs in
`lab/gns3/results/`, fix the driver in `run.py` (or the generator in `generate.js`), run
`python3 lab/gns3/selftest.py` (needs root and strongSwan for the live part), and rerun with
`--nodes <the failing pair>`. Use `--reuse` to retest without rebuilding;
it also skips the config push, so after a generator or config-driver change run without it.

Each node is a VM that takes RAM (see README); run subsets with `--nodes`.
