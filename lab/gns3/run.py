#!/usr/bin/env python3
"""
IPsec Tunnelmatch GNS3 lab: builds a full-mesh topology on a GNS3 server, pushes the
configs the tool generated (lab/gns3/generate.js) over the node consoles, and checks
every tunnel: SAs up, negotiated algorithms as expected, and traffic both ways.

    python3 lab/gns3/run.py [--config lab/gns3/lab.json] [--profile strongest]
                            [--keep] [--reuse] [--nodes iosxe,strongswan] [--dry-run]

Python 3.9+ standard library only (telnetlib is gone in 3.13, so a small telnet
client is included). Needs Node.js for the plan, and a GNS3 2.2 or 3.x server with
the templates named in the lab config.

Results: lab/gns3/results/latest.md, latest.json and one console log per node.
Pre-shared keys are random per run and are masked in every log.
"""

import argparse
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")

NAMES = {"iosxe": "TM-IOSXE", "asa": "TM-ASA", "opnsense": "TM-OPNSENSE", "pfsense": "TM-PFSENSE", "strongswan": "TM-STRONGSWAN"}
LAYOUT = {"iosxe": (-300, -150), "asa": (300, -150), "opnsense": (300, 150), "pfsense": (0, 250), "strongswan": (-300, 150)}


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------- GNS3 API


class Gns3:
    """GNS3 REST client for API v3 (token auth) and v2 (no auth or basic auth)."""

    def __init__(self, url, user=None, password=None):
        self.url = url.rstrip("/")
        self.user, self.password = user, password
        self.token = None
        # GNS3 3.x answers /v3/version without a login; 2.2 has no /v3 (or answers 401 to
        # everything when auth is on), so anything else means v2 with basic auth.
        self.v = "v3"
        try:
            ver = self._raw("GET", "/v3/version")
        except urllib.error.URLError as e:
            raise SystemExit(f"Cannot reach the GNS3 server at {self.url}: {e.reason}. Check server.url and that gns3server is running.")
        except RuntimeError:
            self.v = "v2"
            ver = self._raw("GET", "/v2/version")
        self.version = ver.get("version", "?")
        if self.v == "v3":
            r = self._raw("POST", "/v3/access/users/authenticate", {"username": user, "password": password})
            self.token = r["access_token"]

    def _raw(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        elif self.user and self.v == "v2":  # 2.2 servers with auth = True in gns3_server.conf
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{self.user}:{self.password}".encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            hint = " (check server.user and server.password in the lab config)" if e.code == 401 else ""
            raise RuntimeError(f"GNS3 {method} {path}: HTTP {e.code}{hint} {e.read().decode(errors='replace')[:300]}") from None

    def api(self, method, path, body=None):
        return self._raw(method, f"/{self.v}{path}", body)

    def templates(self):
        return self.api("GET", "/templates")

    def template(self, name=None, ttype=None):
        for t in self.templates():
            if (name and t["name"] == name) or (ttype and t["template_type"] == ttype and t.get("builtin")):
                return t
        return None

    def ensure_docker_template(self, name, image, compute_id):
        t = self.template(name)
        if t:
            return t
        log(f"  creating docker template {name} ({image})")
        return self.api("POST", "/templates", {
            "name": name, "template_type": "docker", "image": image, "compute_id": compute_id,
            "adapters": 1, "console_type": "telnet", "start_command": "/bin/bash", "category": "guest",
        })

    def project_by_name(self, name):
        return next((p for p in self.api("GET", "/projects") if p["name"] == name), None)

    def create_project(self, name):
        old = self.project_by_name(name)
        if old:
            log(f"  deleting old project {name}")
            self.api("DELETE", f"/projects/{old['project_id']}")
        return self.api("POST", "/projects", {"name": name})

    def open_project(self, pid):
        return self.api("POST", f"/projects/{pid}/open")

    def nodes(self, pid):
        return self.api("GET", f"/projects/{pid}/nodes")

    def add_node(self, pid, template_id, name, x, y, compute_id):
        n = self.api("POST", f"/projects/{pid}/templates/{template_id}", {"x": x, "y": y, "name": name, "compute_id": compute_id})
        if n.get("name") != name:  # GNS3 3.0 ignores the name here and uses the template's format
            n = self.api("PUT", f"/projects/{pid}/nodes/{n['node_id']}", {"name": name})
        return n

    def add_link(self, pid, a, b):
        return self.api("POST", f"/projects/{pid}/links", {"nodes": [
            {"node_id": a[0], "adapter_number": a[1], "port_number": a[2]},
            {"node_id": b[0], "adapter_number": b[1], "port_number": b[2]},
        ]})

    def start_all(self, pid):
        return self.api("POST", f"/projects/{pid}/nodes/start")

    def stop_all(self, pid):
        return self.api("POST", f"/projects/{pid}/nodes/stop")

    def console(self, pid, node_id):
        n = self.api("GET", f"/projects/{pid}/nodes/{node_id}")
        host = n.get("console_host") or ""
        if host in ("", "0.0.0.0", "::", "0:0:0:0:0:0:0:0"):
            host = urlparse(self.url).hostname
        return host, n["console"], n.get("console_type")

    def aux(self, pid, node_id):
        """Docker nodes' auxiliary telnet console (GNS3 runs it with `docker exec`), or None."""
        n = self.api("GET", f"/projects/{pid}/nodes/{node_id}")
        port = n.get("aux") or (n.get("properties") or {}).get("aux")
        if not port:
            return None
        host = n.get("console_host") or ""
        if host in ("", "0.0.0.0", "::", "0:0:0:0:0:0:0:0"):
            host = urlparse(self.url).hostname
        return host, port


# --------------------------------------------------------------------------- telnet console

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]")


class Console:
    """Minimal telnet client: answers option negotiation, keeps a text buffer, expect()."""

    def __init__(self, host, port, logfile, secrets=()):
        self.sock = socket.create_connection((host, int(port)), timeout=30)
        self.sock.settimeout(0.3)
        self.buf = ""
        self.secrets = [s for s in secrets if s]
        self.log = open(logfile, "a", encoding="utf-8")
        self._sb = False
        self._pending = b""
        self._answered = {}  # (cmd, opt) -> reply already sent; never answer the same thing twice

    def close(self):
        try:
            self.sock.close()
        finally:
            self.log.close()

    def _mask(self, text):
        for s in self.secrets:
            text = text.replace(s, "<PSK>")
        return text

    def _negotiate(self, data):
        data = self._pending + data
        self._pending = b""
        out, reply, i = bytearray(), bytearray(), 0
        while i < len(data):
            b = data[i]
            if self._sb:
                if b == IAC and i + 1 < len(data) and data[i + 1] == SE:
                    self._sb = False
                    i += 2
                    continue
                i += 1
                continue
            if b != IAC:
                out.append(b)
                i += 1
                continue
            if i + 1 >= len(data):
                self._pending = data[i:]
                break
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
            elif cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data):
                    self._pending = data[i:]
                    break
                opt = data[i + 2]
                # Answer each request once. Some servers (GNS3's own) confirm every DO with
                # another WILL, so answering confirmations again would loop forever.
                if cmd in (DO, WILL) and (cmd, opt) not in self._answered:
                    if cmd == DO:
                        ans = bytes([IAC, WONT, opt])
                    else:
                        ans = bytes([IAC, DO if opt in (1, 3) else DONT, opt])  # accept ECHO and SGA
                    self._answered[(cmd, opt)] = ans
                    reply += ans
                i += 3
            elif cmd == SB:
                self._sb = True
                i += 2
            else:
                i += 2
        if reply:
            self.sock.sendall(bytes(reply))
        return bytes(out)

    def _read(self):
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return False
        if not data:
            raise ConnectionError("console closed")
        text = self._negotiate(data).decode("utf-8", errors="replace")
        text = ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "")
        self.buf += text
        self.log.write(self._mask(text))
        self.log.flush()
        return True

    def send(self, text):
        self.log.write(self._mask(f"\n[tmlab >>> {text.rstrip()}]\n") if text.strip() else "")
        self.sock.sendall(text.encode())

    def sendline(self, line="", eol="\r"):
        self.send(line + eol)

    def expect(self, patterns, timeout):
        """Wait for the first of the regexes; returns (index, match, text before and including it)."""
        pats = [re.compile(p, re.M) if isinstance(p, str) else p for p in patterns]
        end = time.time() + timeout
        while True:
            best = None
            for i, p in enumerate(pats):
                m = p.search(self.buf)
                if m and (best is None or m.start() < best[1].start()):
                    best = (i, m)
            if best:
                i, m = best
                text = self.buf[: m.end()]
                self.buf = self.buf[m.end():]
                return i, m, text
            if time.time() > end:
                raise TimeoutError(f"none of {[p.pattern for p in pats]} within {timeout}s; last output: {self.buf[-300:]!r}")
            self._read()

    def drain(self, quiet=1.0, limit=10.0):
        """Read until no text arrives for `quiet` seconds (at most `limit` seconds), then clear the buffer."""
        start = last = time.time()
        while time.time() - last < quiet and time.time() - start < limit:
            before = len(self.buf)
            self._read()
            if len(self.buf) > before:
                last = time.time()
        self.buf = ""


# --------------------------------------------------------------------------- output parsers

ENC = {"AES_GCM_16": "AES-GCM", "AES_CBC": "AES-CBC", "AES-GCM": "AES-GCM", "AES-CBC": "AES-CBC", "3DES": "3DES"}
SW_HASH = {"PRF_HMAC_SHA1": "SHA1", "PRF_HMAC_SHA2_256": "SHA256", "PRF_HMAC_SHA2_384": "SHA384", "PRF_HMAC_SHA2_512": "SHA512",
           "HMAC_SHA1_96": "SHA1", "HMAC_SHA2_256_128": "SHA256", "HMAC_SHA2_384_192": "SHA384", "HMAC_SHA2_512_256": "SHA512",
           "PRF_HMAC_MD5": "MD5", "HMAC_MD5_96": "MD5"}
SW_DH = {"MODP_1024": 2, "MODP_1536": 5, "MODP_2048": 14, "MODP_3072": 15, "ECP_256": 19, "ECP_384": 20, "ECP_521": 21, "MODP_2048_256": 24}
CISCO_HASH = {"SHA96": "SHA1", "SHA1": "SHA1", "SHA256": "SHA256", "SHA384": "SHA384", "SHA512": "SHA512", "MD5": "MD5", "MD596": "MD5"}


def _cisco_hash(v):
    if v is None:
        return None
    v = v.upper().replace("-", "")
    return None if v in ("NONE", "N/A", "NULL") else CISCO_HASH.get(v, v)


def parse_cisco_ikev2(text, peer):
    """`show crypto ikev2 sa detailed` (IOS-XE) or `show crypto ikev2 sa detail` (ASA), for one peer."""
    rows = re.split(r"(?m)^(?=\s*\d+\s+\d+\.\d+\.\d+\.\d+/\d+\s)", text)
    for row in rows:
        head = re.match(r"\s*\d+\s+(\S+)/\d+\s+(\S+)/\d+\s.*?\b(READY|ACTIVE|UP[-\w]*|IN-NEG\S*|DELETE)\b", row)
        if not head or head.group(2) != peer:
            continue
        ike = {"state": head.group(3)}
        m = re.search(r"Encr(?:yption)?: ([\w-]+), keysize: (\d+)(?:, PRF: ([\w-]+))?, Hash: ([\w/-]+), DH Grp:\s*(\d+)", row)
        if m:
            ike.update({"encr": f"{ENC.get(m.group(1), m.group(1))}-{m.group(2)}", "dh": int(m.group(5)),
                        "integ": _cisco_hash(m.group(4))})
            if m.group(3):
                ike["prf"] = _cisco_hash(m.group(3))
        child = re.search(r"Child sa:.*?Encr: ([\w-]+), keysize: (\d+), esp_hmac: ([\w/-]+)", row, re.S)
        esp = {}
        if child:
            esp = {"encr": f"{ENC.get(child.group(1), child.group(1))}-{child.group(2)}", "integ": _cisco_hash(child.group(3))}
        return {"ike": ike, "esp": esp}
    return None


def parse_cisco_ipsec(text):
    """`show crypto ipsec sa peer X` (IOS-XE and ASA): packet counters, transform and PFS."""
    out = {}
    m = re.search(r"#pkts encaps: (\d+)", text)
    if m:
        out["encaps"] = int(m.group(1))
    m = re.search(r"#pkts decaps: (\d+)", text)
    if m:
        out["decaps"] = int(m.group(1))
    m = re.search(r"transform: esp-(gcm|aes)\s+(\d+)\s*(esp-(\w+)-hmac)?", text)
    if m:
        out["encr"] = ("AES-GCM-" if m.group(1) == "gcm" else "AES-CBC-") + m.group(2)
        out["integ"] = _cisco_hash(m.group(4)) if m.group(4) else None
    m = re.search(r"transform: esp-aes-gcm-(\d+)", text)  # ASA spelling
    if m:
        out["encr"], out["integ"] = "AES-GCM-" + m.group(1), None
    m = re.search(r"DH group: group(\d+)", text) or re.search(r"PFS Group:?\s*(\d+)", text)
    if m:
        out["pfs"] = int(m.group(1))
    return out


def parse_swanctl_raw(raw, peer):
    """`swanctl --list-sas --raw`: the IKE SA toward `peer` and its child SAs."""
    field = lambda s, k: (re.search(r"(?:^|[ {])" + re.escape(k) + r"=(\S+?)(?=[ }]|$)", s) or [None, None])[1]

    def algs(s, ike):
        encr = field(s, "encr-alg")
        out = {}
        if encr:
            out["encr"] = f"{ENC.get(encr, encr)}-{field(s, 'encr-keysize')}"
        integ = field(s, "integ-alg")
        out["integ"] = SW_HASH.get(integ, integ) if integ else None
        if ike:
            prf = field(s, "prf-alg")
            if prf:
                out["prf"] = SW_HASH.get(prf, prf)
        dh = field(s, "dh-group")
        if dh:
            out["dh" if ike else "pfs"] = SW_DH.get(dh, dh)
        return out

    for line in raw.splitlines():
        if not line.startswith("list-sa event {"):
            continue
        body = line[len("list-sa event {"):]
        at = body.find("child-sas {")
        head = body if at < 0 else body[:at]
        if field(head, "remote-host") != peer:
            continue
        ike = algs(head, True)
        ike["state"] = field(head, "state")
        esp, counters = {}, {}
        if at >= 0:
            kids = body[at:]
            installed = [m.group(0) for m in re.finditer(r"[\w.-]+ \{[^{}]*state=INSTALLED[^{}]*\}", kids)]
            if installed:
                esp = algs(installed[0], False)
                counters = {"encaps": sum(int(field(k, "packets-out") or 0) for k in installed),
                            "decaps": sum(int(field(k, "packets-in") or 0) for k in installed)}
        return {"ike": ike, "esp": esp, "counters": counters}
    return None


def ping_ok(text):
    """Received count from Cisco, FreeBSD or Linux ping output."""
    m = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)", text)
    if m:
        return int(m.group(2)), int(m.group(3))
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    if m:
        return int(m.group(2)), int(m.group(1))
    return 0, 0


# --------------------------------------------------------------------------- device drivers


class Driver:
    prompt = r"[#$] ?$"
    boot_answers = []  # (regex, reply) handled while waiting for the device

    def __init__(self, node, plan, con):
        self.node, self.plan, self.con = node, plan, con
        self.errors = []

    def run(self, cmd, timeout=60):
        self.con.sendline(cmd)
        _, _, text = self.con.expect([self.prompt], timeout)
        # drop the echoed command line
        return text.split("\n", 1)[1] if "\n" in text else ""

    def write_file(self, path, content, decode):
        b64 = base64.b64encode(content.encode()).decode()
        self.run(f"rm -f {path}.b64")
        for i in range(0, len(b64), 64):
            self.run(f"echo {b64[i:i + 64]} >> {path}.b64")
        self.run(decode.format(src=path + ".b64", dst=path))


class IosXe(Driver):
    prompt = r"^[\w.-]+(\([\w-]+\))?#\s*$"

    def login(self, timeout):
        answers = [
            (r"initial configuration dialog\? \[yes/no\]:", "no"),
            (r"terminate autoinstall\? \[yes\]:", "yes"),
            (r"Press RETURN to get started", ""),
            (r"^[\w.-]+>\s*$", "enable"),
        ]
        end = time.time() + timeout
        self.con.sendline()
        while time.time() < end:
            try:
                i, _, _ = self.con.expect([a[0] for a in answers] + [self.prompt], 20)
            except TimeoutError:
                self.con.sendline()
                continue
            if i == len(answers):
                self.run("terminal length 0")
                self.run("terminal width 0")
                return
            self.con.sendline(answers[i][1])
        raise TimeoutError("IOS-XE did not reach the privileged prompt")

    def apply(self):
        self.run("configure terminal")
        for line in self.node["lines"]:
            out = self.run(line, 60)
            for err in re.findall(r"(?m)^% (?:Invalid|Incomplete|Ambiguous|Unknown|Error|ERROR).*$", out):
                self.errors.append(f"{line.strip()} → {err.strip()}")
        self.run("end")

    def ping(self, src, dst):
        return ping_ok(self.run(f"ping {dst} source Loopback1 repeat 5 timeout 1", 60))

    def sas(self, peer):
        ike = parse_cisco_ikev2(self.run("show crypto ikev2 sa detailed", 60), peer)
        ipsec = parse_cisco_ipsec(self.run(f"show crypto ipsec sa peer {peer}", 60))
        if not ike:
            return None
        esp = {k: ipsec[k] for k in ("encr", "integ", "pfs") if k in ipsec}
        return {"ike": ike["ike"], "esp": esp or ike["esp"], "counters": {k: ipsec[k] for k in ("encaps", "decaps") if k in ipsec}}


class Asa(Driver):
    prompt = r"^[\w.-]+(\([\w-]+\))?#\s*$"

    def login(self, timeout):
        pw = self.node.get("enable_password", "")
        answers = [
            (r"\[Y\]es, \[N\]o, \[A\]sk later:", "N"),
            (r"Enter\s+Password:", pw),
            (r"Repeat\s+Password:", pw),
            (r"^Password:\s*$", pw),
            (r"Invalid password", ""),
            (r"^[\w.-]+>\s*$", "enable"),
        ]
        end = time.time() + timeout
        self.con.sendline()
        while time.time() < end:
            try:
                i, _, _ = self.con.expect([a[0] for a in answers] + [self.prompt], 20)
            except TimeoutError:
                self.con.sendline()
                continue
            if i == len(answers):
                self.run("terminal pager 0")
                return
            self.con.sendline(answers[i][1])
        raise TimeoutError("ASA did not reach the privileged prompt")

    def run(self, cmd, timeout=60):
        # the anonymous-reporting question can show up on the first "configure terminal"
        self.con.sendline(cmd)
        text = ""
        while True:
            i, _, t = self.con.expect([self.prompt, r"\[Y\]es, \[N\]o, \[A\]sk later:"], timeout)
            text += t
            if i == 0:
                break
            self.con.sendline("N")
        return text.split("\n", 1)[1] if "\n" in text else ""

    def apply(self):
        self.run("configure terminal")
        for line in self.node["lines"]:
            out = self.run(line, 60)
            for err in re.findall(r"(?m)^ERROR:.*$", out):
                self.errors.append(f"{line.strip()} → {err.strip()}")
        self.run("end")

    def ping(self, src, dst):
        return ping_ok(self.run(f"ping inside {dst} repeat 5 timeout 2", 60))

    def sas(self, peer):
        ike = parse_cisco_ikev2(self.run("show crypto ikev2 sa detail", 60), peer)
        ipsec = parse_cisco_ipsec(self.run(f"show crypto ipsec sa peer {peer}", 60))
        if not ike:
            return None
        esp = dict(ike["esp"])
        esp.update({k: ipsec[k] for k in ("encr", "integ", "pfs") if k in ipsec})
        return {"ike": ike["ike"], "esp": esp, "counters": {k: ipsec[k] for k in ("encaps", "decaps") if k in ipsec}}


class Shell(Driver):
    """Shared by OPNsense and strongSwan: a POSIX shell with our own prompt."""

    prompt = r"^TMLAB# $"

    def set_prompt(self):
        self.con.sendline("PS1='TMLAB# '; export PS1")
        self.con.expect([self.prompt], 30)

    def sas(self, peer):
        return parse_swanctl_raw(self.run("swanctl --list-sas --raw", 60), peer)


class FreeBsdFirewall(Shell):
    """OPNsense and pfSense: console menu, option 8 for a shell, then a PHP script that
    writes the plan into the firewall's own config, and a full reload."""

    product = "firewall"
    apply_script = None
    apply_steps = ["php /tmp/tmlab_apply.php /tmp/tmlab.json"]
    reload_cmds = []
    shell_prompt = r"^\S*@\S*:.*[#%$] $|^# $"

    def login(self, timeout):
        user, pw = self.node.get("user", "root"), self.node.get("password", "")
        answers = [
            (r"login:\s*$", user),
            (r"^Password:\s*$", pw),
            (r"Enter an option:\s*$", "8"),
            (self.shell_prompt, "/bin/sh"),
        ]
        end = time.time() + timeout
        self.con.sendline()
        while time.time() < end:
            try:
                i, _, _ = self.con.expect([a[0] for a in answers], 20)
            except TimeoutError:
                self.con.sendline()
                continue
            self.con.sendline(answers[i][1])
            if i == 3:
                self.set_prompt()
                return
        raise TimeoutError(f"{self.product} did not reach a shell")

    def apply(self):
        decode = "openssl base64 -d -in {src} -out {dst}"
        with open(os.path.join(HERE, self.apply_script), encoding="utf-8") as f:
            self.write_file("/tmp/tmlab_apply.php", f.read(), decode)
        self.write_file("/tmp/tmlab.json", json.dumps(self.node["data"]), decode)
        for step in self.apply_steps:
            out = self.run(step + "; echo TMLAB-EXIT=$?", 300)
            for bad in re.findall(r"(?m)^TMLAB-INVALID.*$", out):
                self.errors.append(bad)
            if "TMLAB-EXIT=0" not in out:
                self.errors.append(f"{self.product} config update failed at `{step}`: " + out.strip()[-300:])
                self.run("rm -f /tmp/tmlab.json /tmp/tmlab.json.b64")  # holds the lab's pre-shared keys
                return
        self.run("rm -f /tmp/tmlab.json /tmp/tmlab.json.b64")
        for cmd in self.reload_cmds:
            self.run(cmd, 600)
        for cmd in self.node["shell"]:
            self.run(cmd, 30)
        conns = self.run("swanctl --list-conns", 60)
        want = len(self.node["data"].get("connections") or self.node["data"].get("tunnels") or [])
        got = len(re.findall(r"(?m)^\S+: IKEv2", conns))
        if got < want:
            self.errors.append(f"swanctl lists {got} IKEv2 connections, expected {want}")

    def ping(self, src, dst):
        return ping_ok(self.run(f"ping -c 5 -W 1000 -S {src} {dst}", 60))


class OpnSense(FreeBsdFirewall):
    product = "OPNsense"
    apply_script = "opnsense_apply.php"
    # enc0 only becomes a valid rule interface after the connections are saved and
    # write_config() has registered the plugin interfaces
    apply_steps = [
        "php /tmp/tmlab_apply.php /tmp/tmlab.json ipsec",
        "/usr/local/sbin/pluginctl -i",  # OPNsense's own "register plugin interfaces and save"
        "php /tmp/tmlab_apply.php /tmp/tmlab.json filter",
    ]
    reload_cmds = ["/usr/local/etc/rc.reload_all", "/usr/local/sbin/pluginctl -c ipsec"]

    def __init__(self, node, plan, con):
        super().__init__(node, plan, con)
        self.node.setdefault("password", "opnsense")


class PfSense(FreeBsdFirewall):
    product = "pfSense"
    apply_script = "pfsense_apply.php"
    reload_cmds = ["/etc/rc.reload_all"]
    # [2.7.2-RELEASE][root@pfSense.home.arpa]/root:
    shell_prompt = r"\]/\S*: $|^\S*@\S*:.*[#%$] $|^# $"


class StrongSwan(Shell):
    def login(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            self.con.sendline()
            try:
                self.con.expect([r"[#$] ?$"], 10)
                self.con.drain(1)
                # the auxiliary console is busybox sh; use the container's bash instead
                self.con.sendline("exec /bin/bash --norc --noprofile -i")
                self.con.expect([r"[#$] ?$"], 15)
                self.con.drain(1)
                self.set_prompt()
                return
            except TimeoutError:
                continue
        raise TimeoutError("strongSwan container gave no shell prompt")

    def apply(self):
        for path, content in self.node["files"].items():
            self.run(f"mkdir -p {os.path.dirname(path)}")
            self.write_file(path, content, "base64 -d {src} > {dst} && rm -f {src}")
        for cmd in self.node["shell"]:
            out = self.run(cmd, 30)
            if re.search(r"(?mi)^(error|cannot|RTNETLINK answers).*", out):
                self.errors.append(f"{cmd} → {out.strip()[:200]}")
        self.run("pkill -x charon-systemd; (/usr/sbin/charon-systemd > /var/log/charon.log 2>&1 &)")
        self.run("sleep 3")
        out = self.run("swanctl --load-all", 60)
        for bad in re.findall(r"(?mi)^.*(?:failed|error).*$", out):
            if "opening directory" not in bad:  # empty credential folders are fine with PSKs
                self.errors.append(f"swanctl --load-all: {bad.strip()}")
        if not re.search(r"loaded connection", out):
            self.errors.append("swanctl --load-all loaded no connections")

    def ping(self, src, dst):
        return ping_ok(self.run(f"ping -c 5 -W 1 -I {src} {dst}", 60))


DRIVERS = {"iosxe": IosXe, "asa": Asa, "opnsense": OpnSense, "pfsense": PfSense, "strongswan": StrongSwan}


# --------------------------------------------------------------------------- checks


def compare(expect, got, keys):
    """Mismatches between the plan and what a device reported; values a device does not report are skipped."""
    bad = []
    for k in keys:
        if k in got and got[k] is not None and k in expect and got[k] != expect[k]:
            bad.append(f"{k} {got[k]} (expected {expect[k]})")
        if k in expect and expect[k] is None and got.get(k):
            bad.append(f"{k} {got[k]} (expected none)")
    return bad


def test_pair(pair, drivers):
    res = {"a": pair["a"], "b": pair["b"], "label": pair.get("label"), "checks": [], "seen": {}}

    def check(ok, text):
        res["checks"].append({"ok": bool(ok), "text": text})

    check(not pair["verdict"]["cryptoErrors"], "Tool reports no crypto errors for this pair")
    for side, other in (("a", "b"), ("b", "a")):
        d = drivers[pair[side]]
        src, dst = pair["ping"][side]["src"], pair["ping"][side]["dst"]
        got = (0, 0)
        for _ in range(4):  # the first packets start the negotiation
            got = d.ping(src, dst)
            if got[0] >= 3:
                break
            time.sleep(5)
        check(got[0] > 0, f"Ping {NAMES[pair[side]]} {src} → {dst}: {got[0]}/{got[1]} replies")
    for side, other in (("a", "b"), ("b", "a")):
        d = drivers[pair[side]]
        sa = d.sas(pair["peers"][other])
        name = NAMES[pair[side]]
        if not sa:
            check(False, f"{name}: no IKE SA toward {pair['peers'][other]}")
            continue
        res["seen"][side] = sa
        check(sa["ike"].get("state") in ("ESTABLISHED", "READY", "UP-ACTIVE"), f"{name}: IKE SA state {sa['ike'].get('state')}")
        bad = compare(pair["expect"]["ike"], sa["ike"], ("encr", "prf", "integ", "dh"))
        check(not bad, f"{name}: IKE {fmt(sa['ike'])}" + (f" — mismatch: {', '.join(bad)}" if bad else ""))
        if sa.get("esp"):
            bad = compare(pair["expect"]["esp"], sa["esp"], ("encr", "integ", "pfs"))
            check(not bad, f"{name}: ESP {fmt(sa['esp'])}" + (f" — mismatch: {', '.join(bad)}" if bad else ""))
        else:
            check(False, f"{name}: no installed child SA")
        c = sa.get("counters") or {}
        if c:
            check(c.get("encaps", 0) > 0 and c.get("decaps", 0) > 0, f"{name}: packets out {c.get('encaps', 0)}, in {c.get('decaps', 0)}")
    res["ok"] = all(c["ok"] for c in res["checks"])
    return res


def fmt(d):
    return " / ".join(str(d[k]) for k in ("encr", "integ", "prf", "dh", "pfs") if d.get(k) is not None)


# --------------------------------------------------------------------------- report


def write_report(meta, nodes, pairs):
    os.makedirs(RESULTS, exist_ok=True)
    lines = [
        "# IPsec Tunnelmatch GNS3 lab",
        "",
        f"{meta['when']} · GNS3 {meta['gns3']} ({meta['api']}) · profile `{meta['profile']}` · "
        f"{sum(p['ok'] for p in pairs)}/{len(pairs)} tunnels passed",
        "",
        "| | Tunnel | Profile | Failed checks |",
        "|---|---|---|---|",
    ]
    for p in pairs:
        failed = [c["text"] for c in p["checks"] if not c["ok"]]
        lines.append(f"| {'✅' if p['ok'] else '❌'} | {NAMES[p['a']]} ↔ {NAMES[p['b']]} | {p.get('label') or p.get('skipped', '')} | {'<br>'.join(failed) or '—'} |")
    lines += ["", "## Nodes", ""]
    for n in nodes:
        lines.append(f"- {'✅' if not n['errors'] else '❌'} **{NAMES[n['id']]}** {n.get('status', '')}")
        lines += [f"  - {e}" for e in n["errors"]]
    for p in pairs:
        lines += ["", f"### {'✅' if p['ok'] else '❌'} {NAMES[p['a']]} ↔ {NAMES[p['b']]}", ""]
        lines += [f"- {'✅' if c['ok'] else '❌'} {c['text']}" for c in p["checks"]]
    md = "\n".join(lines) + "\n"
    with open(os.path.join(RESULTS, "latest.md"), "w", encoding="utf-8") as f:
        f.write(md)
    with open(os.path.join(RESULTS, "latest.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "nodes": nodes, "pairs": pairs}, f, indent=2)
    return md


# --------------------------------------------------------------------------- main


def check_docker_image(g, compute, image):
    """The strongSwan node needs its image in the GNS3 server's Docker."""
    try:
        have = [i.get("image") for i in g.api("GET", f"/computes/{compute}/docker/images")]
    except Exception as e:
        sys.exit(f"Could not list Docker images on GNS3 compute '{compute}': {e}\n"
                 "Is Docker installed on the GNS3 server, and is the GNS3 user in the docker group?")
    want = image if ":" in image else image + ":latest"
    if want not in have:
        sys.exit(f"Docker image '{want}' not found on the GNS3 server. Build it there:\n"
                 f"  docker build -t {want.split(':')[0]} lab/gns3/strongswan\n"
                 f"Images GNS3 sees: {', '.join(sorted(have)) or 'none'}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None, help="lab config (default lab/gns3/lab.json, else lab.example.json)")
    ap.add_argument("--profile", default=None, help="strongest (default), recommended or minimum")
    ap.add_argument("--nodes", default=None, help="comma-separated subset, e.g. iosxe,strongswan")
    ap.add_argument("--keep", action="store_true", help="leave the project running afterwards")
    ap.add_argument("--reuse", action="store_true", help="use the existing project and running nodes; skip build and config push")
    ap.add_argument("--dry-run", action="store_true", help="generate the plan and check the GNS3 server and templates only")
    opt = ap.parse_args()

    cfg_path = opt.config or (os.path.join(HERE, "lab.json") if os.path.exists(os.path.join(HERE, "lab.json")) else os.path.join(HERE, "lab.example.json"))
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    user_cfg = cfg_path
    if opt.nodes:
        keep = set(opt.nodes.split(","))
        for k, n in cfg["nodes"].items():
            n["enabled"] = n.get("enabled", True) and k in keep
        cfg_path = os.path.join(HERE, "out", "lab.selected.json")
        os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

    gen = ["node", os.path.join(HERE, "generate.js"), "--config", cfg_path]
    if opt.profile:
        gen += ["--profile", opt.profile]
    subprocess.run(gen, check=True)
    with open(os.path.join(HERE, "out", "plan.json"), encoding="utf-8") as f:
        plan = json.load(f)
    secrets = sorted({c["psk"] for n in plan["nodes"].values() for key in ("connections", "tunnels")
                      for c in n.get("data", {}).get(key, [])} |
                     set(re.findall(r"pre-shared-key (\w+)", json.dumps(plan))) |
                     set(re.findall(r'secret = \\"(\w+)\\"', json.dumps(plan))))

    srv = plan["server"]
    g = Gns3(srv["url"], srv.get("user"), srv.get("password"))
    compute = srv.get("compute_id", "local")
    log(f"GNS3 {g.version} at {srv['url']} (API {g.v})")

    ids = list(plan["nodes"])
    templates = {}
    for nid in ids:
        n = plan["nodes"][nid]
        if nid == "strongswan":
            check_docker_image(g, compute, n["image"])
            t = g.template(n["template"])
            if not t and opt.dry_run:
                t = {"name": n["template"] + " (created on the real run)"}
            elif not t:
                t = g.ensure_docker_template(n["template"], n["image"], compute)
        else:
            t = g.template(n["template"])
        if not t and nid != "strongswan":
            # the appliance wizard adds the version, e.g. "OPNsense" -> "OPNsense 26.1"
            close = [x for x in g.templates() if not x.get("builtin") and x["name"].startswith(n["template"] + " ")]
            if len(close) == 1:
                t = close[0]
                log(f"  {nid}: using template '{t['name']}' (set nodes.{nid}.template to it to silence this)")
        if not t:
            names = sorted(x["name"] for x in g.templates() if not x.get("builtin"))
            sys.exit(f"Template '{n['template']}' for {nid} not found on the GNS3 server. Import the appliance or fix "
                     f"nodes.{nid}.template in {user_cfg}.\nTemplates on the server: " + (", ".join(f"'{x}'" for x in names) or "none (no appliances imported yet)")
                     + f"\nTo leave {nid} out for now: --nodes " + ",".join(k for k in ids if k != nid))
        templates[nid] = t
    switch = g.template(ttype="ethernet_switch")
    log("Templates: " + ", ".join(f"{nid}={templates[nid]['name']}" for nid in ids))
    if opt.dry_run:
        log("Dry run: plan generated, server and templates found.")
        return

    os.makedirs(RESULTS, exist_ok=True)
    meta = {"when": time.strftime("%Y-%m-%d %H:%M"), "gns3": g.version, "api": g.v, "profile": plan["profile"]}
    project = g.project_by_name(plan["project"]) if opt.reuse else None
    if opt.reuse and not project:
        sys.exit(f"--reuse: no project named {plan['project']}")

    if not project:
        log(f"Building project {plan['project']}")
        project = g.create_project(plan["project"])
        pid = project["project_id"]
        wan = g.add_node(pid, switch["template_id"], "TM-WAN", 0, 0, compute)
        port = 0
        made = {}
        for nid in ids:
            n = plan["nodes"][nid]
            x, y = LAYOUT[nid]
            made[nid] = g.add_node(pid, templates[nid]["template_id"], NAMES[nid], x, y, compute)
            g.add_link(pid, (made[nid]["node_id"], n["wan_port"]["adapter"], n["wan_port"]["port"]), (wan["node_id"], 0, port))
            port += 1
            if n.get("lan_port"):
                lan = g.add_node(pid, switch["template_id"], f"TM-LAN-{nid.upper()}", x * 2, y * 2, compute)
                g.add_link(pid, (made[nid]["node_id"], n["lan_port"]["adapter"], n["lan_port"]["port"]), (lan["node_id"], 0, 0))
        log("Starting nodes")
        g.start_all(pid)
    else:
        pid = project["project_id"]
        g.open_project(pid)

    by_name = {n["name"]: n for n in g.nodes(pid)}
    drivers, node_results = {}, []
    for nid in ids:
        n = plan["nodes"][nid]
        host, port, ctype = g.console(pid, by_name[NAMES[nid]]["node_id"])
        if nid == "strongswan":
            # The main console of a docker node goes through Docker's attach websocket, which
            # gave no prompt with GNS3 2.2.61 on Ubuntu 24.04's Docker. The auxiliary console
            # is a plain `docker exec`, so use that when there is one.
            aux = g.aux(pid, by_name[NAMES[nid]]["node_id"])
            if aux:
                host, port = aux
                log(f"{NAMES[nid]}: using the auxiliary console ({host}:{port})")
        logfile = os.path.join(RESULTS, f"{nid}.log")
        with open(logfile, "w", encoding="utf-8") as f:  # one run per log, not appended
            f.write(f"# {NAMES[nid]} console {host}:{port}, run started {meta['when']}\n")
        con = Console(host, port, logfile, secrets)
        d = DRIVERS[nid](n, plan, con)
        drivers[nid] = d
        nr = {"id": nid, "errors": d.errors}
        node_results.append(nr)
        try:
            log(f"{NAMES[nid]}: waiting for console ({host}:{port}, up to {n.get('boot_timeout', 900)} s)")
            d.login(n.get("boot_timeout", 900))
            if not opt.reuse:
                log(f"{NAMES[nid]}: applying config")
                d.apply()
            nr["status"] = "configured" if not d.errors else "configured with errors"
        except Exception as e:  # keep going: the other nodes can still be tested
            d.errors.append(f"{type(e).__name__}: {e}")
            nr["status"] = "failed"
        log(f"{NAMES[nid]}: {nr['status']}" + (f" ({len(d.errors)} errors)" if d.errors else ""))

    log("Waiting 20 s for the tunnels to settle")
    time.sleep(20)
    results = []
    for pair in plan["pairs"]:
        if pair.get("skipped"):
            results.append({"a": pair["a"], "b": pair["b"], "ok": False, "skipped": pair["skipped"], "checks": []})
            continue
        down = [NAMES[pair[s]] for s in ("a", "b") if dict((n["id"], n) for n in node_results)[pair[s]].get("status") == "failed"]
        if down:
            results.append({"a": pair["a"], "b": pair["b"], "label": pair.get("label"), "ok": False,
                            "checks": [{"ok": False, "text": f"Not tested: {', '.join(down)} could not be configured"}]})
            log(f"SKIP  {NAMES[pair['a']]} ↔ {NAMES[pair['b']]}")
            continue
        try:
            r = test_pair(pair, drivers)
        except Exception as e:
            r = {"a": pair["a"], "b": pair["b"], "label": pair.get("label"), "ok": False,
                 "checks": [{"ok": False, "text": f"{type(e).__name__}: {e}"}]}
        results.append(r)
        log(f"{'PASS' if r['ok'] else 'FAIL'}  {NAMES[pair['a']]} ↔ {NAMES[pair['b']]}")

    for d in drivers.values():
        d.con.close()
    md = write_report(meta, node_results, results)
    log("\n" + md.split("\n## Nodes")[0])
    if not opt.keep:
        g.stop_all(pid)
        log("Nodes stopped (project kept for inspection; use --keep to leave them running).")
    sys.exit(0 if results and all(r["ok"] for r in results) else 1)


if __name__ == "__main__":
    main()
