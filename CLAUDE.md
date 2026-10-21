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

## GNS3 lab on this server

This machine is the GNS3 server (GNS3 2.2.61, Ubuntu 24.04 on Proxmox, server runs as root).
The repo is at /home/demo/ipsec-tunnelmatch. Config: `lab/gns3/lab.json` (copied from
`lab.example.json`, git-ignored).

```sh
git pull
python3 lab/gns3/selftest.py --parsers-only        # quick sanity check
python3 lab/gns3/run.py --dry-run                 # plan + check server and templates
python3 lab/gns3/run.py --nodes strongswan,opnsense --keep
```

Node addressing (WAN 203.0.113.x, LAN 10.x.0.0/24): iosxe .11 / 10.1, asa .12 / 10.2,
opnsense .13 / 10.3, strongswan .14 / 10.4, pfsense .15 / 10.5, mikrotik .16 / 10.6,
vsrx .17 / 10.7, vyos .18 / 10.8, openwrt .19 / 10.9.

Status:
- OPNsense 26.1 <-> strongSwan: passed on real images 2026-10-20
  (`lab/gns3/reference/2026-10-20-opnsense-strongswan.md`).
- pfSense 2.7.2: template prep in progress (`prepare_template.py`, see README).
- MikroTik CHR, vSRX, VyOS, OpenWrt, IOS-XE, ASA: drivers tested only against simulated
  consoles. Expect small fixes (prompts, show-command formats) on the first real run.

When a run fails: read `lab/gns3/results/latest.md` and the per-node console logs in
`lab/gns3/results/`, fix the driver in `run.py` (or the generator in `generate.js`), run
`python3 lab/gns3/selftest.py` (needs root and strongSwan for the live part), and rerun with
`--nodes <the failing pair>`. Use `--reuse` to retest without rebuilding.

Each node is a VM that takes RAM (see README); run subsets with `--nodes`.
