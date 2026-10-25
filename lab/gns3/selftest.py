#!/usr/bin/env python3
"""
Self-test for the GNS3 lab runner, without GNS3 or vendor images.

1. Parsers: Cisco IOS-XE / ASA show output (format as in Cisco's configuration
   examples; not captured from a live device) and real `swanctl --list-sas --raw`.
2. Console and strongSwan driver end to end: two Linux network namespaces stand in
   for two GNS3 nodes. Each gets a bash behind a small telnet bridge, and run.py's
   own Console and StrongSwan driver log in, push the tool's configs, start charon,
   ping across the tunnel and read the SAs back, exactly as they would on GNS3.

    sudo python3 lab/gns3/selftest.py           # needs root, node, strongSwan (see .github/workflows/lab.yml)
    python3 lab/gns3/selftest.py --parsers-only # no root needed
"""

import json
import os
import pty
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run  # noqa: E402

FAILS = []
PASSES = []


def check(ok, text):
    print(f"{'PASS' if ok else 'FAIL'}  {text}", flush=True)
    PASSES.append(ok)
    if not ok:
        FAILS.append(text)
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error::GNS3 self-test: {text}".replace("\n", "%0A"), flush=True)


# --------------------------------------------------------------------------- 1. parsers

IOSXE_IKEV2 = """
 IPv4 Crypto IKEv2  SA

Tunnel-id Local                 Remote                fvrf/ivrf            Status
1         203.0.113.11/500      203.0.113.12/500      none/none            READY
      Encryption: AES-GCM, keysize: 256, PRF: SHA384, Hash: None, DH Grp:20, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 28800/31 sec
      CE id: 1001, Session-id: 1

Tunnel-id Local                 Remote                fvrf/ivrf            Status
2         203.0.113.11/500      203.0.113.14/500      none/none            READY
      Encr: AES-CBC, keysize: 256, PRF: SHA256, Hash: SHA256, DH Grp:14, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 28800/12 sec
"""

IOSXE_IPSEC = """
interface: GigabitEthernet1
    Crypto map tag: CMAP, local addr 203.0.113.11

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (10.1.0.0/255.255.255.0/0/0)
   remote ident (addr/mask/prot/port): (10.2.0.0/255.255.255.0/0/0)
   current_peer 203.0.113.12 port 500
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 9, #pkts encrypt: 9, #pkts digest: 9
    #pkts decaps: 9, #pkts decrypt: 9, #pkts verify: 9

     local crypto endpt.: 203.0.113.11, remote crypto endpt.: 203.0.113.12
     current outbound spi: 0xC1D2E3F4(3251823604)
     PFS (Y/N): Y, DH group: group20

     inbound esp sas:
      spi: 0x1A2B3C4D(439041101)
        transform: esp-gcm 256 ,
        in use settings ={Tunnel, }
"""

ASA_IKEV2 = """
IKEv2 SAs:

Session-id:3, Status:UP-ACTIVE, IKE count:1, CHILD count:1

Tunnel-id                 Local                                               Remote                                                  Status         Role
 52671203 203.0.113.12/500                                    203.0.113.11/500                                        READY    RESPONDER
      Encr: AES-GCM, keysize: 256, Hash: N/A, DH Grp:20, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 28800/40 sec
      Session-id: 3
      Status Description: Negotiation done
      Child sa: local selector  10.2.0.0/0 - 10.2.0.255/65535
          remote selector 10.1.0.0/0 - 10.1.0.255/65535
          ESP spi in/out: 0x2d4f6a8b/0x9c1e3f5a
          AH spi in/out: 0x0/0x0
          CPI in/out: 0x0/0x0
          Encr: AES-GCM, keysize: 256, esp_hmac: N/A
          ah_hmac: None, comp: IPCOMP_NONE, mode tunnel
"""

ASA_IPSEC = """
peer address: 203.0.113.11
    Crypto map tag: OUTSIDE_MAP, seq num: 10, local addr: 203.0.113.12

      #pkts encaps: 5, #pkts encrypt: 5, #pkts digest: 5
      #pkts decaps: 5, #pkts decrypt: 5, #pkts verify: 5
"""


# RouterOS 7 print detail format as documented; not captured from a device.
ROS_PEERS = """Flags: R - RESPONDER; N - NATT-PEER
 0    id="203.0.113.14" local-address=203.0.113.16 port=500 remote-address=203.0.113.14 port=500 state=established
      side=initiator uptime=2m10s last-seen=5s ph2-total=1
"""

ROS_SAS = """Flags: S - SEEN-TRAFFIC; H - HW-AEAD; E - IKE
 0 SE  spi=0xC0FFEE01 src-address=203.0.113.14 dst-address=203.0.113.16 state=mature auth-algorithm=null
       enc-algorithm=aes-gcm enc-key-size=288 add-lifetime=48m/1h replay=128 current-bytes=840
 1 SE  spi=0xC0FFEE02 src-address=203.0.113.16 dst-address=203.0.113.14 state=mature auth-algorithm=null
       enc-algorithm=aes-gcm enc-key-size=288 add-lifetime=48m/1h replay=128 current-bytes=760
"""


# Junos detail output in the layout of Juniper's documentation; not captured from a device.
JUNOS_IKE = """IKE peer 203.0.113.14, Index 5, Gateway Name: GW-STRONGSWAN
  Role: Initiator, State: UP
  Exchange type: IKEv2, Authentication method: Pre-shared-keys
  Local: 203.0.113.17:500, Remote: 203.0.113.14:500
  Algorithms:
   Authentication        : hmac-sha384-192
   Encryption            : aes256-cbc
   Pseudo random function: hmac-sha384
   Diffie-Hellman group  : DH-group-20
"""

JUNOS_IPSEC = """  ID: 500001 Virtual-system: root, VPN Name: VPN-STRONGSWAN
  Local Gateway: 203.0.113.17, Remote Gateway: 203.0.113.14
  Local Identity: ipv4(10.7.0.0-10.7.0.255)
    Direction: inbound, SPI: 0x8a1b2c3d, AUX-SPI: 0
    Protocol: ESP, Authentication: none, Encryption: aes-gcm (256 bits)
    PFS (group): DH-group-20
"""

# PAN-OS output in the layout of published samples (packetswitch.co.uk, majornetwork.net);
# not captured from a device. The GCM row wraps the way a narrow terminal shows it.
PANOS_IKE = """There is no IKEv1 phase-1 SA found.

IKEv2 SAs
Gateway ID      Peer-Address           Gateway Name           Role SN       Algorithm          Established     Expiration      Xt Child  ST
----------      ------------           ------------           ---- --       ---------          -----------     ----------      -- -----  --
1               203.0.113.14           GW-STRONGSWAN
Init 40       PSK/DH20/AES256-GCM16/COMBINED Oct.23 07:47:31 Oct.23 15:47:31 0  1      Established
2               203.0.113.16           GW-MIKROTIK            Resp 41       PSK/DH20/A256/SHA384 Oct.23 07:48:02 Oct.23 15:48:02 0  1      Established

IKEv2 IPSec Child SAs
Show IKEv2 SA: Total 2 gateways found. 2 ike sa found.
"""

PANOS_IPSEC = """GwID/client IP  TnID   Peer-Address           Tunnel(Gateway)                                Algorithm          SPI(in)  SPI(out) life(Sec/KB)             remain-time(Sec)
--------------  ----   ------------           ---------------                                ---------          -------  -------- ------------             ----------------
1               4      203.0.113.14           TUN-STRONGSWAN:PID-1(GW-STRONGSWAN)            ESP/G256/ /DH20    D6899B03 1BF46826 3600/Unlimited           3517
2               5      203.0.113.16           TUN-MIKROTIK:PID-1(GW-MIKROTIK)                ESP/A256/SHA256/DH14 C0FFEE01 C0FFEE02 3600/Unlimited         3530

Show IPSec SA: Total 2 tunnels found. 2 ipsec sa found.
"""

PANOS_FLOW = """tunnel  TUN-STRONGSWAN:PID-1
        id:                     4
        type:                   IPSec
        encap packets:          25
        decap packets:          24
"""

# both ends initiated at once: a CONNECTING duplicate listed before the established IKE_SA
SWANCTL_TWO_SAS = (
    "list-sa event {opnsense {uniqueid=2 version=2 state=CONNECTING local-host=203.0.113.14 local-port=500 "
    "remote-host=203.0.113.13 remote-port=500 initiator=yes initiator-spi=1a2b3c4d5e6f7081 responder-spi=0000000000000000 "
    "child-sas {}}}\n"
    "list-sa event {opnsense {uniqueid=1 version=2 state=ESTABLISHED local-host=203.0.113.14 local-port=4500 "
    "remote-host=203.0.113.13 remote-port=4500 initiator-spi=013f0f36ce63f929 responder-spi=9db5f2f12bda2cdb "
    "encr-alg=AES_GCM_16 encr-keysize=256 prf-alg=PRF_HMAC_SHA2_384 dh-group=ECP_384 established=40 "
    "child-sas {opnsense-1-2 {name=opnsense-1 uniqueid=2 reqid=1 state=INSTALLED mode=TUNNEL protocol=ESP "
    "encr-alg=AES_GCM_16 encr-keysize=256 packets-in=5 packets-out=5 local-ts=[10.4.0.0/24] remote-ts=[10.3.0.0/24]}}}}\n"
    "list-sas reply {}\n"
)

# strongSwan 6.1 with VyOS (2026-10-23): both ends initiated and both IKE_SAs stay ESTABLISHED;
# the traffic runs on the second one
SWANCTL_TWO_ESTABLISHED = (
    "list-sa event {vyos {uniqueid=2 version=2 state=ESTABLISHED local-host=203.0.113.14 local-port=4500 "
    "remote-host=203.0.113.18 remote-port=4500 initiator-spi=27256f2518952475 responder-spi=28770b982c496644 "
    "encr-alg=AES_GCM_16 encr-keysize=256 prf-alg=PRF_HMAC_SHA2_384 dh-group=ECP_384 established=29 "
    "child-sas {vyos-1-2 {name=vyos-1 uniqueid=2 reqid=1 state=INSTALLED mode=TUNNEL protocol=ESP "
    "encr-alg=AES_GCM_16 encr-keysize=256 packets-in=0 packets-out=0 local-ts=[10.4.0.0/24] remote-ts=[10.8.0.0/24]}}}}\n"
    "list-sa event {vyos {uniqueid=1 version=2 state=ESTABLISHED local-host=203.0.113.14 local-port=4500 "
    "remote-host=203.0.113.18 remote-port=4500 initiator=yes initiator-spi=d2ff5bd3f9ae8679 responder-spi=aa43c7b318c2d495 "
    "encr-alg=AES_GCM_16 encr-keysize=256 prf-alg=PRF_HMAC_SHA2_384 dh-group=ECP_384 established=22 "
    "child-sas {vyos-1-3 {name=vyos-1 uniqueid=3 reqid=1 state=INSTALLED mode=TUNNEL protocol=ESP "
    "encr-alg=AES_GCM_16 encr-keysize=256 packets-in=10 packets-out=10 local-ts=[10.4.0.0/24] remote-ts=[10.8.0.0/24]}}}}\n"
    "list-sas reply {}\n"
)


def test_parsers():
    r = run.parse_cisco_ikev2(IOSXE_IKEV2, "203.0.113.12")
    check(r and r["ike"] == {"state": "READY", "encr": "AES-GCM-256", "prf": "SHA384", "integ": None, "dh": 20},
          f"IOS-XE ikev2 sa (GCM): {r and r['ike']}")
    r = run.parse_cisco_ikev2(IOSXE_IKEV2, "203.0.113.14")
    check(r and r["ike"]["encr"] == "AES-CBC-256" and r["ike"]["integ"] == "SHA256" and r["ike"]["dh"] == 14,
          f"IOS-XE ikev2 sa (CBC, 'Encr:' spelling): {r and r['ike']}")
    check(run.parse_cisco_ikev2(IOSXE_IKEV2, "203.0.113.99") is None, "IOS-XE ikev2 sa: unknown peer gives None")
    r = run.parse_cisco_ipsec(IOSXE_IPSEC)
    check(r == {"encaps": 9, "decaps": 9, "encr": "AES-GCM-256", "integ": None, "pfs": 20}, f"IOS-XE ipsec sa: {r}")
    r = run.parse_cisco_ikev2(ASA_IKEV2, "203.0.113.11")
    check(r and r["ike"] == {"state": "READY", "encr": "AES-GCM-256", "integ": None, "dh": 20} and r["esp"] == {"encr": "AES-GCM-256", "integ": None},
          f"ASA ikev2 sa detail: {r}")
    r = run.parse_cisco_ipsec(ASA_IPSEC)
    check(r == {"encaps": 5, "decaps": 5}, f"ASA ipsec sa: {r}")
    r = run.parse_junos(JUNOS_IKE, JUNOS_IPSEC, "203.0.113.14")
    check(r and r["ike"] == {"state": "ESTABLISHED", "encr": "AES-CBC-256", "prf": "SHA384", "integ": "SHA384", "dh": 20}
          and r["esp"] == {"encr": "AES-GCM-256", "integ": None, "pfs": 20}, f"Junos ike/ipsec security-associations: {r}")
    check(run.parse_junos(JUNOS_IKE, JUNOS_IPSEC, "203.0.113.99") is None, "Junos: unknown peer gives None")
    r = run.parse_routeros_sas(ROS_PEERS, ROS_SAS, "203.0.113.16", "203.0.113.14")
    check(r == {"ike": {"state": "ESTABLISHED"}, "esp": {"encr": "AES-GCM-256", "integ": None},
                "counters": {"encaps": 760, "decaps": 840}}, f"RouterOS active-peers / installed-sa: {r}")
    check(run.parse_routeros_sas(ROS_PEERS, ROS_SAS, "203.0.113.16", "203.0.113.99") is None, "RouterOS: unknown peer gives None")
    r = run.parse_swanctl_raw(SWANCTL_TWO_SAS, "203.0.113.13")
    check(r and r["ike"]["state"] == "ESTABLISHED" and r["esp"] == {"encr": "AES-GCM-256", "integ": None}
          and r["counters"] == {"encaps": 5, "decaps": 5}, f"swanctl: established IKE_SA preferred over a CONNECTING duplicate: {r}")
    check(run.parse_swanctl_raw(SWANCTL_TWO_SAS, "203.0.113.99") is None, "swanctl: unknown peer gives None")
    r = run.parse_swanctl_raw(SWANCTL_TWO_ESTABLISHED, "203.0.113.18")
    check(r and r["counters"] == {"encaps": 10, "decaps": 10}, f"swanctl: of two ESTABLISHED IKE_SAs, the one with traffic: {r}")
    check(r and r["pairs"] == 1, f"swanctl: the same subnet pair on both IKE_SAs counts once: {r and r['pairs']}")
    two = SWANCTL_TWO_ESTABLISHED.replace("remote-ts=[10.8.0.0/24]}}}}\nlist-sa event {vyos {uniqueid=1", "remote-ts=[10.8.100.0/24]}}}}\nlist-sa event {vyos {uniqueid=1")
    r = run.parse_swanctl_raw(two, "203.0.113.18")
    check(r and r["pairs"] == 2, f"swanctl: subnet pairs spread over two IKE_SAs are both counted: {r and r['pairs']}")
    aged = SWANCTL_TWO_ESTABLISHED.replace("state=INSTALLED mode=TUNNEL", "state=INSTALLED install-time=17 mode=TUNNEL", 1)
    r = run.parse_swanctl_ages(aged, "203.0.113.18")
    check(r == {"ike_sas": 2, "ike_oldest": 29, "child_sas": 2, "child_oldest": 17}, f"swanctl SA ages: {r}")
    r = run.parse_panos(PANOS_IKE, PANOS_IPSEC, "203.0.113.14")
    check(r == {"ike": {"state": "ESTABLISHED", "dh": 20, "encr": "AES-GCM-256", "integ": None},
                "esp": {"encr": "AES-GCM-256", "integ": None, "pfs": 20}, "counters": {}, "tunnels": [4]},
          f"PAN-OS ike-sa / ipsec-sa (GCM, wrapped row): {r}")
    r = run.parse_panos(PANOS_IKE, PANOS_IPSEC, "203.0.113.16")
    check(r and r["ike"] == {"state": "ESTABLISHED", "dh": 20, "encr": "AES-CBC-256", "integ": "SHA384"}
          and r["esp"] == {"encr": "AES-CBC-256", "integ": "SHA256", "pfs": 14} and r["tunnels"] == [5],
          f"PAN-OS ike-sa / ipsec-sa (CBC): {r}")
    check(run.parse_panos(PANOS_IKE, PANOS_IPSEC, "203.0.113.99") is None, "PAN-OS: unknown peer gives None")
    check(run.parse_panos_flow(PANOS_FLOW) == {"encaps": 25, "decaps": 24}, "PAN-OS vpn flow counters")
    check(run.ping_ok("5 packets transmitted, 5 received, 0% packet loss, time 4006ms") == (5, 5), "PAN-OS ping")
    check(run.ping_ok("  SEQ HOST    SIZE TTL TIME\n    sent=5 received=4 packet-loss=20% min-rtt=1ms") == (4, 5), "RouterOS ping")
    check(run.ping_ok("Success rate is 80 percent (4/5), round-trip min/avg/max = 1/2/4 ms") == (4, 5), "Cisco ping")
    check(run.ping_ok("5 packets transmitted, 5 packets received, 0.0% packet loss") == (5, 5), "FreeBSD ping")
    check(run.ping_ok("5 packets transmitted, 3 received, 40% packet loss, time 4005ms") == (3, 5), "Linux ping")
    exp = {"encr": "AES-GCM-256", "prf": "SHA384", "integ": None, "dh": 20}
    check(run.compare(exp, {"encr": "AES-GCM-256", "dh": 20}, ("encr", "prf", "integ", "dh")) == [], "compare skips values a device does not report")
    check(run.compare(exp, {"encr": "AES-GCM-256", "dh": 19}, ("encr", "dh")) == ["dh 19 (expected 20)"], "compare reports a mismatch")


# --------------------------------------------------------------------------- 2. live strongSwan pair

NS = {"left": "tmg-left", "right": "tmg-right"}


def sh(*cmd, check_=True):
    return subprocess.run(cmd, check=check_, capture_output=True, text=True)


class Bridge(threading.Thread):
    """Telnet-ish server: each connection gets an interactive bash inside a network,
    mount and PID namespace, like a GNS3 docker console."""

    def __init__(self, ns, setup):
        super().__init__(daemon=True)
        self.ns, self.setup = ns, setup
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]

    def run(self):
        conn, _ = self.srv.accept()
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp("ip", ["ip", "netns", "exec", self.ns, "unshare", "-m", "-p", "-f", "--mount-proc",
                             "--propagation", "private", "sh", "-c", self.setup + "; exec bash --norc --noprofile -i"])
        conn.sendall(bytes([255, 251, 1, 255, 251, 3]))  # IAC WILL ECHO, IAC WILL SGA, like a real console
        while True:
            r, _, _ = select.select([conn, fd], [], [], 1)
            try:
                if conn in r:
                    data = conn.recv(4096)
                    if not data:
                        break
                    data = bytes(b for b in data)  # replies to our negotiation are harmless to bash
                    os.write(fd, data.replace(bytes([255, 253, 1]), b"").replace(bytes([255, 253, 3]), b""))
                if fd in r:
                    conn.sendall(os.read(fd, 4096))
            except OSError:
                break


def tool_configs(profile):
    """Both sides' swanctl configs from the tool, through generate.js's own strongSwan merge."""
    js = r"""
const { loadTool } = require("../tm.js");
const { BASE, RECOMMENDED, MINIMUM } = require("../scenarios.js");
const TM = loadTool();
const prof = process.argv[1] === "minimum" ? MINIMUM : RECOMMENDED;
const S = JSON.parse(JSON.stringify(Object.assign({}, BASE, prof, { tunnelName: "SELFTEST" })));
S.A = { name: "LEFT", vendor: "strongswan", ip: "203.0.113.21", nets: "10.21.0.0/24", mode: "policy", tun: "10" };
S.B = { name: "RIGHT", vendor: "strongswan", ip: "203.0.113.22", nets: "10.22.0.0/24", mode: "policy", tun: "10" };
const R = TM.analyze(S);
const out = {};
for (const k of ["A", "B"]) out[k] = TM.vendor("strongswan").generate(TM.contextFor(S, k, R));
console.log(JSON.stringify(out));
"""
    r = subprocess.run(["node", "-e", js, profile], cwd=HERE, check=True, capture_output=True, text=True)
    return json.loads(r.stdout)


def file_name(conf):
    """The file name generate.js gives a tool config (same regex), so the self-test covers it."""
    js = "const t=require('fs').readFileSync(0,'utf8');const m=t.match(/^# \\/etc\\/swanctl\\/conf\\.d\\/([\\w.-]+\\.conf)\\b/m);process.stdout.write(m?m[1]:'')"
    name = subprocess.run(["node", "-e", js], input=conf, capture_output=True, text=True, check=True).stdout
    check(name.endswith(".conf") and "," not in name, f"strongSwan config file name: {name!r}")
    return name


def node_plan(me, peer, text, psk):
    lan = {"left": "10.21.0", "right": "10.22.0"}
    wan = {"left": "203.0.113.21", "right": "203.0.113.22"}
    conf = text.replace("<PSK>", psk)
    name = file_name(conf)
    return {
        "files": {f"/etc/swanctl/conf.d/{name}": conf + "\n"},
        "shell": [
            "ip link set lo up; ip addr add %s.1/32 dev lo" % lan[me],
            "ip route replace %s.0/24 via %s src %s.1" % (lan[peer], wan[peer], lan[me]),
        ],
    }, wan, lan


def test_live(profile, libipsec):
    for ns in NS.values():
        sh("ip", "netns", "del", ns, check_=False)
        sh("ip", "netns", "add", ns)
    sh("ip", "link", "add", "tmg0", "netns", NS["left"], "type", "veth", "peer", "name", "tmg1", "netns", NS["right"])
    for side, ifn, ip in (("left", "tmg0", "203.0.113.21"), ("right", "tmg1", "203.0.113.22")):
        sh("ip", "-n", NS[side], "link", "set", ifn, "name", "eth0")
        sh("ip", "-n", NS[side], "addr", "add", ip + "/24", "dev", "eth0")
        sh("ip", "-n", NS[side], "link", "set", "eth0", "up")

    tmp = tempfile.mkdtemp(prefix="tmg-")
    conf = os.path.join(tmp, "strongswan.conf")
    with open(conf, "w") as f:
        f.write("charon {\n  load_modular = yes\n  journal { default = -1 }\n  plugins {\n    include /etc/strongswan.d/charon/*.conf\n"
                + ("    kernel-libipsec { load = yes }\n" if libipsec else "") + "  }\n}\n")
    # private /run and /etc/swanctl per node, as separate containers would have
    setup = (f"mount -t tmpfs tmpfs /run && mount -t tmpfs tmpfs /etc/swanctl && mkdir -p /etc/swanctl/conf.d "
             f"&& echo 'include conf.d/*.conf' > /etc/swanctl/swanctl.conf && export STRONGSWAN_CONF={conf}")

    cfgs = tool_configs(profile)
    psk = os.urandom(16).hex()
    drivers = {}
    for side, k, peer in (("left", "A", "right"), ("right", "B", "left")):
        br = Bridge(NS[side], setup)
        br.start()
        plan, wan, lan = node_plan(side, peer, cfgs[k], psk)
        con = run.Console("127.0.0.1", br.port, os.path.join(tmp, f"{side}.log"), [psk])
        d = run.StrongSwan(plan, {}, con)
        d.login(30)
        d.apply()
        check(not d.errors, f"{side}: driver applied the tool's config ({d.errors or 'no errors'})")
        drivers[side] = d

    expect = {"recommended": {"ike": {"encr": "AES-GCM-256", "prf": "SHA384", "integ": None, "dh": 20},
                              "esp": {"encr": "AES-GCM-256", "integ": None, "pfs": 20}},
              "minimum": {"ike": {"encr": "AES-CBC-256", "prf": "SHA256", "integ": "SHA256", "dh": 14},
                          "esp": {"encr": "AES-CBC-256", "integ": "SHA256", "pfs": 14}}}[profile]
    pair = {
        "a": "strongswan", "b": "strongswan2", "label": profile, "expect": expect,
        "verdict": {"cryptoErrors": []},
        "pings": {"a": [{"src": "10.21.0.1", "dst": "10.22.0.1"}], "b": [{"src": "10.22.0.1", "dst": "10.21.0.1"}]},
        "peers": {"a": "203.0.113.21", "b": "203.0.113.22"},
    }
    run.NAMES["strongswan2"] = "TM-STRONGSWAN-2"
    res = run.test_pair(pair, {"strongswan": drivers["left"], "strongswan2": drivers["right"]})
    for c in res["checks"]:
        check(c["ok"], f"[{profile}{', libipsec' if libipsec else ''}] {c['text']}")
    log = open(os.path.join(tmp, "left.log")).read()
    check(psk not in log, "pre-shared key is masked in the console log")
    for d in drivers.values():
        d.run("pkill -x charon-systemd; true")
        d.con.close()
    for ns in NS.values():
        sh("ip", "netns", "del", ns, check_=False)
    return res["ok"]


def main():
    test_parsers()
    if "--parsers-only" not in sys.argv:
        if os.geteuid() != 0:
            sys.exit("Run as root for the live test, or pass --parsers-only.")
        libipsec = "--kernel" not in sys.argv
        for profile in ("recommended", "minimum"):
            test_live(profile, libipsec)
    print(f"\n{'All checks passed' if not FAILS else str(len(FAILS)) + ' checks failed'}")
    if os.environ.get("GITHUB_ACTIONS") and not FAILS:
        print(f"::notice::GNS3 driver self-test: all {len(PASSES)} checks passed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
