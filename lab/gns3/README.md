# GNS3 lab: generated configs on real appliances

This lab takes the configs the tool generates and runs them on real virtual appliances in GNS3, in a full mesh:

```
                 TM-WAN (switch, 203.0.113.0/24)
     ┌──────────────┬──────────────┬──────────────┐
  TM-IOSXE        TM-ASA       TM-OPNSENSE   TM-STRONGSWAN
  .11             .12           .13           .14
  Lo1 10.1.0.1    inside        LAN           lo
                  10.2.0.1      10.3.0.1      10.4.0.1
```

Every pair of nodes gets a policy-based tunnel (6 tunnels with all four nodes). For each pair the plan uses the **strongest common profile**, the same one the tool's "Use strongest profile both sides support" button picks. Between these four platforms that is the recommended baseline: AES-256-GCM, PRF SHA-384, group 20, ESP AES-256-GCM, PFS group 20. `--profile minimum` runs AES-256-CBC / SHA-256 / group 14 instead.

For every tunnel it checks:

1. the tool reports no crypto errors for the pair
2. ping from each LAN to the other LAN works, in both directions
3. both ends show the IKE SA up, with the encryption, PRF, integrity and DH group the plan expects
4. both ends show the child SA with the expected ESP algorithm (and the PFS group where the device reports it)
5. packets were encrypted and decrypted on both ends

It also checks that every config line was accepted: IOS-XE `%` errors, ASA `ERROR:` lines, OPNsense model validation and `swanctl --load-all` errors are all reported per node.

## Status

| Part | Tested |
|---|---|
| Plan generation (`generate.js`) | In CI on every push |
| GNS3 API client (v3) | Against GNS3 server 3.0.6: projects, nodes from templates, renaming, links, start, consoles, docker template creation |
| Telnet console and strongSwan driver | In CI: two network namespaces stand in for two GNS3 nodes, and real tunnels come up with the tool's configs (`selftest.py`) |
| IOS-XE, ASA and OPNsense drivers | **Not yet run against real images.** Prompts, commands and output parsers follow Cisco and OPNsense documentation and the OPNsense source; the parsers are tested against sample output in that format, not output captured from a device |

The first runs on real images will probably need small fixes in the drivers (a prompt or a show-command format). Please report what you find with the console logs in `lab/gns3/results/`.

## What you need

- A GNS3 server, 2.2 or 3.x (GNS3 VM, bare metal or Proxmox), reachable from where you run the lab, with KVM for the QEMU appliances.
- Python 3.9 or later (standard library only) and Node.js 18 or later on the machine that runs the lab.
- Templates (import the GNS3 marketplace appliances; you supply the images):
  - **Cisco Catalyst 8000V** (IOS-XE 17.x). Runs without a licence at limited throughput. If `crypto ikev2` commands are rejected, add `license boot level network-advantage` to `extra_config`, save and reload once.
  - **Cisco ASAv** (9.x). Runs without a licence at limited throughput.
  - **OPNsense** (nano/serial image, 24.7 or later): LAN on `vtnet0`, WAN on `vtnet1`, login `root` / `opnsense`.
  - **strongSwan**: build the image on the GNS3 host, `docker build -t tunnelmatch-strongswan lab/gns3/strongswan`. The lab creates the docker template itself if it is missing. ESP runs in the host kernel (XFRM).
- About 12 GB RAM for all four nodes (C8000v 4 GB, ASAv 2 GB, OPNsense 2 GB, container minimal).

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
| `wan_port`, `lan_port` | GNS3 adapter and port numbers for WAN and LAN links (defaults match the marketplace appliances: C8000v adapter 0 = Gi1; ASAv adapter 0 = Management0/0, 1 = Gi0/0, 2 = Gi0/1; OPNsense adapter 0 = vtnet0, 1 = vtnet1) |
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
- **OPNsense**: the tool's Connections field values are read back into the MVC models (`OPNsense\IPsec\Swanctl` and `OPNsense\IPsec\IPsec`) by `opnsense_apply.php`, which runs on the firewall through the console shell. The models validate every value, so a proposal string the GUI would not offer fails the run. It also sets the interface addresses, turns off the bogon/private blocks on WAN (203.0.113.0/24 is a documentation range), enables IPsec and adds a pass rule on the IPsec interface.
- **strongSwan**: the tool's `swanctl.conf` per peer in `/etc/swanctl/conf.d/`, LAN address on `lo`, `charon-systemd` and `swanctl --load-all`.

## Self-test without GNS3

```sh
sudo python3 lab/gns3/selftest.py                 # parsers + live strongSwan driver test (root, strongSwan installed)
python3 lab/gns3/selftest.py --parsers-only
```
