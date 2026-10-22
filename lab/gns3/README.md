# GNS3 lab: generated configs on real appliances

This lab takes the configs the tool generates and runs them on real virtual appliances in GNS3, in a full mesh:

```
                                  TM-WAN (switch, 203.0.113.0/24)
   IOS-XE .11   ASA .12   OPNsense .13   strongSwan .14   pfSense .15
   MikroTik .16   vSRX .17   VyOS .18   OpenWrt .19

   LANs: 10.1.0.0/24 (IOS-XE) … 10.9.0.0/24 (OpenWrt), one /24 per node, on a loopback,
   dummy or empty-bridge interface, or on a small switch of its own (ASA, OPNsense,
   pfSense, OpenWrt)
```

Every pair of nodes gets a tunnel (36 with all nine nodes), policy-based wherever the platform has it; Junos is route-based with one traffic selector per peer. For each pair the plan uses the **strongest common profile**, the same one the tool's "Use strongest profile both sides support" button picks. Between most of these platforms that is the recommended baseline (with MikroTik and vSRX, IKE uses AES-256-CBC with SHA-384): AES-256-GCM, PRF SHA-384, group 20, ESP AES-256-GCM, PFS group 20. `--profile minimum` runs AES-256-CBC / SHA-256 / group 14 instead.

For every tunnel it checks:

1. the tool reports no crypto errors for the pair
2. ping from each LAN to the other LAN works, in both directions
3. both ends show the IKE SA up, with the encryption, PRF, integrity and DH group the plan expects
4. both ends show the child SA with the expected ESP algorithm (and the PFS group where the device reports it)
5. packets were encrypted and decrypted on both ends

It also checks that every config line was accepted: IOS-XE `%` errors, ASA `ERROR:` lines, OPNsense model validation, pfSense algorithm checks and `swanctl --load-all` errors are all reported per node.

## Status

| Part | Tested |
|---|---|
| Plan generation (`generate.js`) | In CI on every push |
| GNS3 API client | Against GNS3 server 3.0.6 and 2.2.61 (with a login): projects, nodes from templates, renaming, links, start, consoles, docker template creation |
| Telnet console and strongSwan driver | In CI: two network namespaces stand in for two GNS3 nodes, and real tunnels come up with the tool's configs (`selftest.py`) |
| pfSense config mapping | The config `pfsense_apply.php` writes was run through pfSense 2.7.2's own proposal code (`ipsec.inc`): it gives `aes256gcm128-sha384-ecp384` / `aes256gcm128-ecp384` (recommended) and `aes256-sha256-modp2048` (minimum), and the strongSwan lab negotiates the expected algorithms from that spelling |
| OPNsense and strongSwan drivers | **Run on real images** (2026-10-20): GNS3 2.2.61 on Proxmox, OPNsense 26.1 ↔ strongSwan container, recommended profile. Tunnel up with IKE AES_GCM_16_256 / PRF_HMAC_SHA2_384 / ECP_384 and ESP AES_GCM_16_256, traffic both ways ([report](reference/2026-10-20-opnsense-strongswan.md)). The first runs found and fixed: enc0 registration before the IPsec rule, explicit WAN rules for IKE/NAT-T/ESP, the docker auxiliary console, telnet option handling, and the strongSwan file name. **OPNsense 26.7.7** ↔ strongSwan passed on 2026-10-22 ([report](reference/2026-10-22-opnsense-26.7-strongswan.md)) with the template `add_templates.py` builds; that run found that a DHCP lease saved in the template during its online update replaced the static WAN address in the lab, so the preparation now deletes the lease files |
| MikroTik driver | **Run on a real CHR** (2026-10-21): RouterOS 7.24.5 with strongSwan, VyOS and OpenWrt, strongest profile, all tunnels up with traffic both ways ([report](reference/2026-10-21-strongswan-mikrotik-vyos-openwrt.md)). The run found that RouterOS 7.24.5 rejects `auth-algorithms=null` for AES-GCM ("AEAD already provides authentication") and accepts `auth-algorithms=""`. The runs used that spelling; **the tool's MikroTik generator does not have it yet** (pending release) |
| VyOS and OpenWrt drivers | **Run on real images** (2026-10-21): VyOS rolling 2026.10.21 (live ISO) and OpenWrt 25.12.6 with strongSwan and MikroTik, all six tunnels of the four-node mesh up ([report](reference/2026-10-21-strongswan-mikrotik-vyos-openwrt.md)). Found on the way, **not yet in the tool's generators** (pending release): OpenWrt needs `kmod-crypto-seqiv` for AES-GCM in ESP, which `strongswan-full` does not pull in (the preparation installs it); `strongswan-full` also enables the legacy `ipsec` service next to `swanctl`, both start charon, and a leftover charon or `swanctl --load-all` can hold UDP 500/4500 (the lab's OpenWrt merge in `generate.js` disables `ipsec` and clears leftovers before restarting `swanctl`); and when both ends initiate, OpenWrt can delete both IKE SAs, so VyOS and strongSwan need `close-action start` to re-initiate |
| vSRX driver | Login, configuration, error detection and parsers tested against a simulated console; **not yet run on a real image** |
| IOS-XE, ASA and pfSense drivers | **Not yet run against real images.** Prompts, commands and output parsers follow Cisco and OPNsense documentation and the OPNsense source; the parsers are tested against sample output in that format, not output captured from a device |

The first runs on real images will probably need small fixes in the drivers (a prompt or a show-command format). Please report what you find with the console logs in `lab/gns3/results/`.

## What you need

- A GNS3 server, 2.2 or 3.x (GNS3 VM, bare metal or Proxmox), reachable from where you run the lab, with KVM for the QEMU appliances.
- Python 3.9 or later (standard library only) and Node.js 18 or later on the machine that runs the lab.
- Templates (import the GNS3 marketplace appliances; you supply the images):
  - **Cisco Catalyst 8000V** (IOS-XE 17.x). Runs without a licence at limited throughput. If `crypto ikev2` commands are rejected, add `license boot level network-advantage` to `extra_config`, save and reload once.
  - **Cisco ASAv** (9.x). Runs without a licence at limited throughput.
  - **OPNsense** (nano image, 24.7 or later): LAN on `vtnet0`, WAN on `vtnet1`, login `root` / `opnsense`. `add_templates.py` builds an up-to-date one, see below.
  - **strongSwan**: build the image on the GNS3 host, `docker build -t tunnelmatch-strongswan lab/gns3/strongswan`. The lab creates the docker template itself if it is missing. ESP runs in the host kernel (XFRM).
  - **pfSense** (2.7.2): needs a one-time install first, see [pfSense](#pfsense-one-time-preparation) below.
  - **MikroTik CHR** (RouterOS 7, `chr-7.x.img` from mikrotik.com/download, free). Runs unlicensed at 1 Mbit/s per interface, plenty for the tests. The lab logs in as `admin` with an empty password on first boot and sets `password` from the config.
  - **Juniper vSRX** (60-day evaluation licence from Juniper). The lab logs in as root without a password on first boot, sets `password` from the config and commits. Give it 4 GB RAM.
  - **VyOS**: the free rolling-release ISO works as a live system (make a QEMU template that boots the ISO, console telnet), or a 1.4/1.5 qcow2 if you have a subscription. The 1.5 appliance template asks for 8 GB RAM; 2 GB is enough for the lab. Login `vyos`/`vyos`.
  - **OpenWrt** (free): the image has no strongSwan, so prepare it once, see [OpenWrt](#openwrt-one-time-preparation).
- About 21 GB RAM for all nine nodes (C8000v 4 GB, ASAv 2 GB, vSRX 4 GB, VyOS 2 GB, OPNsense 2 GB, pfSense 2 GB, CHR 384 MB, OpenWrt 128 MB, container minimal). Use `--nodes` to run a subset.

## Free appliances: `add_templates.py`

MikroTik CHR, VyOS, OpenWrt and OPNsense can be set up in one step:

```sh
python3 lab/gns3/add_templates.py                    # all four; --only mikrotik,vyos,openwrt,opnsense
```

For each one it downloads the newest stable free image (CHR from the version in `NEWESTa7.stable`, the newest `generic-amd64` ISO from `vyos/vyos-nightly-build`, OpenWrt's `stable_version` x86/64 ext4 image, the newest OPNsense release's nano image), checks the published SHA-256, uploads it through the GNS3 API and creates the QEMU template named in the lab config (telnet console; KVM when the server has it). It then boots a test node of each new template in a scratch project and waits for the login prompt on the console. For OpenWrt it also does the [one-time preparation](#openwrt-one-time-preparation) below, so you end up with both `OpenWrt` and `OpenWrt (tmlab)`. For OPNsense it boots the base template with its WAN on a NAT node and runs the GUI's firmware update (`opnsense-update -pt opnsense`, then base and kernel with a reboot) until nothing is pending, and turns that disk into `OPNsense <version> (tmlab)`. The prep projects are deleted afterwards.

Existing templates are skipped; `--replace` recreates them. Downloads are cached in `~/.cache/tunnelmatch-gns3`. `--no-check` skips the test boot, `--no-prepare` stops after the base OpenWrt or OPNsense template.

| Template | Image | Settings |
|---|---|---|
| MikroTik CHR | `chr-<version>.img` | 384 MB, 1 vCPU, virtio disk, 4 × virtio-net-pci (adapter 0 = ether1, WAN) |
| VyOS | rolling ISO as a live system (CD-ROM, boot from `d`, no disk) | 2048 MB, 2 vCPU, 3 × virtio-net-pci (adapter 0 = eth0, WAN). The ISO's default boot entry already puts the console on ttyS0 (`vyos login:` on the telnet console), so no GRUB or kernel options are needed |
| OpenWrt | `openwrt-<version>-x86-64-generic-ext4-combined.img` | 256 MB, 1 vCPU, virtio disk, 2 × virtio-net-pci (adapter 0 = eth0 LAN, adapter 1 = eth1 WAN) |
| OPNsense | `OPNsense-<version>-nano-amd64.img`, updated to the newest minor release | 2048 MB, 1 vCPU, virtio disk, 4 × virtio-net-pci (adapter 0 = vtnet0 LAN, adapter 1 = vtnet1 WAN) |

It does not need root: the GNS3 server stores the uploads itself, and `prepare_template.py` fetches the prepared disk through the API when it cannot read the server's project folder.

## pfSense: one-time preparation

The GNS3 pfSense appliance is the installer ISO with a VNC console, so the lab cannot boot it as it is. Install it once and turn the installed disk into a template:

1. Import the **pfSense** appliance (version 2.7.2, `pfSense-CE-2.7.2-RELEASE-amd64.iso`) on the main server.
2. Create a GNS3 project named `pfsense-prep` with one pfSense node. Start it and open its console (VNC).
   If your ISO is the Netgate online installer rather than the offline `pfSense-CE-2.7.2-RELEASE` ISO, also connect `em0` to a GNS3 **NAT** node so the installer can reach the internet.
3. Install with the defaults and reboot. If it asks about VLANs, answer `n`; WAN is `em0`, LAN is `em1` (the defaults).
4. At the console menu choose **8) Shell** and turn on the serial console, which the lab uses:
   ```sh
   php -r 'require_once("config.inc"); require_once("pfsense-utils.inc"); config_set_path("system/enableserial", true); config_set_path("system/primaryconsole", "serial"); write_config("Serial console"); console_configure();'
   exit
   ```
5. Choose **6) Halt system**, wait until it is off, and stop the node in GNS3.
6. On the GNS3 server machine:
   ```sh
   python3 lab/gns3/prepare_template.py --project pfsense-prep --name "pfSense 2.7.2 (tmlab)"
   ```
   This copies the installed disk into the GNS3 images folder and creates the template **pfSense 2.7.2 (tmlab)** (no ISO, telnet console), the name `lab.example.json` already uses. You can delete the prep project afterwards.

In the lab, pfSense is configured by `pfsense_apply.php` through the console shell: interface addresses, bogon/private blocks off on WAN, one phase 1 per peer and one phase 2 per subnet pair (the same `config.xml` entries the Tunnels pages write, from the tool's pfSense fields), and a pass rule on the IPsec tab. The GUI's form validation does not run there; the script checks every algorithm against pfSense's own lists instead.

## OpenWrt: one-time preparation

The OpenWrt image has no strongSwan. `add_templates.py` does these steps for you; by hand, install it once with internet access and turn the disk into a template:

1. Import the **OpenWrt** appliance. In a GNS3 project named `openwrt-prep`, add one OpenWrt node and connect its **eth1 (WAN)** to a **NAT** node. Start it and open the console.
2. Install strongSwan (OpenWrt 25.x uses `apk`, 24.x and older `opkg`):
   ```sh
   apk update && apk add strongswan-full kmod-crypto-seqiv          # 25.x
   opkg update && opkg install strongswan-full kmod-crypto-seqiv    # 24.x
   ```
   `kmod-crypto-seqiv` is needed for AES-GCM in ESP; `strongswan-full` does not pull it in, and without it the kernel refuses the SA ("unable to initialize cryptographic operations").
3. Run `poweroff`, wait, and stop the node.
4. On the GNS3 server machine: `python3 lab/gns3/prepare_template.py --project openwrt-prep --name "OpenWrt (tmlab)"`

## Not automated

- **Sophos Firewall** and **IPFire** are in the tool, but not in the lab. Both are set up through their web interface (Sophos also needs an online registration, and the GNS3 IPFire appliance is from 2019), so test them by hand with the tool's field values and report the result with **Report a working configuration**.
- **Left out on purpose:** IPCop, Smoothwall Express, ZeroShell and ClearOS (no longer maintained, IKEv1-era stacks), Untangle (IPsec is a paid add-on), and router images without an IKE daemon (FRR, VPP, Infix). OpenWrt-based NethSecurity would test the same strongSwan setup as OpenWrt.

## Run it

```sh
cp lab/gns3/lab.example.json lab/gns3/lab.json   # then set the server URL, credentials and template names
python3 lab/gns3/run.py --dry-run                 # plan + check the server and templates
python3 lab/gns3/run.py                           # build, configure, test (first boot takes 10-20 minutes)
```

Options:

| Option | What it does |
|---|---|
| `--profile strongest\|recommended\|minimum` | Crypto profile for every pair (default `strongest`) |
| `--nodes iosxe,strongswan` | Only these nodes (and the tunnels between them) |
| `--keep` | Leave the nodes running afterwards |
| `--reuse` | Use the existing project and its running nodes; skip the build and config push and only test |
| `--dry-run` | Generate the plan and check the server and templates, nothing else |

`run.py` deletes and recreates the project named in the config (default `tunnelmatch-lab`), so do not reuse that name for anything else.

Output in `lab/gns3/results/`: `latest.md` (summary and every check), `latest.json`, and the full console log per node. `lab/gns3/out/` holds the plan and one config file per node (`iosxe.txt`, `asa.txt`, …) that you can also paste by hand. Pre-shared keys are random per run, written only to `out/` (git-ignored) and masked as `<PSK>` in the logs.

## Configuration

`lab.example.json` has one block per node:

| Field | Meaning |
|---|---|
| `enabled` | Include the node |
| `template` | GNS3 template name |
| `wan_port`, `lan_port` | GNS3 adapter and port numbers for WAN and LAN links (defaults match the marketplace appliances: C8000v adapter 0 = Gi1; ASAv adapter 0 = Management0/0, 1 = Gi0/0, 2 = Gi0/1; OPNsense adapter 0 = vtnet0, 1 = vtnet1; pfSense adapter 0 = em0, 1 = em1) |
| `wan_if`, `lan_if` | Interface names on the device |
| `wan_ip`, `lan`, `lan_ip` | Addressing |
| `extra_config` | Extra IOS-XE or ASA lines, sent before the generated config |
| `enable_password` | ASA enable password (set on first boot if the ASA asks) |
| `user`, `password` | OPNsense console login |
| `boot_timeout` | Seconds to wait for the console prompt |

## How each node is configured

All configs come from the tool's own generators (the same code the page runs, loaded by `lab/tm.js`). Because one device has several peers, `generate.js` merges the per-tunnel output:

- **IOS-XE**: one crypto map entry per peer (`CMAP 10, 20, 30`) and one IKEv2 policy listing every proposal, because IOS-XE chooses the IKEv2 policy by local address, not by peer. Static routes send each remote LAN toward its peer. LAN is `Loopback1`.
- **ASA**: one IKEv2 policy priority and one crypto map sequence per peer, `nameif outside/inside`, `management-access inside` so the ASA answers pings on its inside address through the tunnel, and routes per remote LAN.
- **pfSense**: the tool's Tunnels field values (for example "AES256-GCM, key length 128 bits") are mapped to `config.xml` values (`aes256gcm`, keylen 128) by `generate.js` and written by `pfsense_apply.php`, followed by `/etc/rc.reload_all`.
- **OPNsense**: the tool's Connections field values are read back into the MVC models (`OPNsense\IPsec\Swanctl` and `OPNsense\IPsec\IPsec`) by `opnsense_apply.php`, which runs on the firewall through the console shell. The models validate every value, so a proposal string the GUI would not offer fails the run. It also sets the interface addresses, turns off the bogon/private blocks on WAN (203.0.113.0/24 is a documentation range), enables IPsec and adds a pass rule on the IPsec interface.
- **MikroTik**: the tool's RouterOS script per peer, flattened to one full-path command per line (`/ip ipsec profile add …`), after the WAN address, an empty bridge `lan0` for the LAN address and static routes. Login is `admin+ct200w` (no colours, no terminal detection, wide lines). RouterOS shows no IKE algorithms in `active-peers`, so for MikroTik the lab checks the IKE state, the ESP algorithm from `installed-sa`, and the IKE algorithms from the peer's side.
- **vSRX**: the tool's `set` commands (route-based on one `st0` unit per peer, traffic selectors, zones `untrust`/`trust`/`vpn`), after the WAN address on `ge-0/0/0`, the LAN on `lo0.0` and host-inbound IKE and ping. No static routes: auto route insertion adds them.
- **VyOS**: the tool's `set vpn ipsec …` commands per peer (shared lines once), after the WAN address, a dummy interface `dum0` for the LAN and static routes; `commit`, SAs read with `swanctl`.
- **OpenWrt**: network and routes via UCI, then the tool's UCI commands (`/etc/config/ipsec`, firewall rules and NAT exemption), firewall and swanctl restarted.
- **strongSwan**: the tool's `swanctl.conf` per peer in `/etc/swanctl/conf.d/`, LAN address on `lo`, `charon-systemd` and `swanctl --load-all`.

## Self-test without GNS3

```sh
sudo python3 lab/gns3/selftest.py                 # parsers + live strongSwan driver test (root, strongSwan installed)
python3 lab/gns3/selftest.py --parsers-only
```
