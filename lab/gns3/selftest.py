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
        "ping": {"a": {"src": "10.21.0.1", "dst": "10.22.0.1"}, "b": {"src": "10.22.0.1", "dst": "10.21.0.1"}},
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
