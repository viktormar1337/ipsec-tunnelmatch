#!/usr/bin/env python3
"""
Creates the GNS3 templates the lab needs for the freely downloadable appliances: MikroTik
CHR, VyOS (rolling ISO, run as a live system), OpenWrt and OPNsense, plus the prepared
"OpenWrt (tmlab)" and "OPNsense <version> (tmlab)".

    python3 lab/gns3/add_templates.py [--only mikrotik,vyos,openwrt,opnsense] [--replace]
                                      [--no-check] [--no-prepare] [--config lab/gns3/lab.json]

For each appliance it downloads the newest stable free image, verifies the published
SHA-256, uploads it through the GNS3 API and creates a QEMU template (telnet console,
KVM) named like the "template" field in the lab config. Existing templates are kept
unless --replace is given. Each new template is booted once in a scratch project
(tmlab-template-check) to confirm the serial console reaches a login prompt.

OpenWrt and OPNsense then get a one-time preparation with internet access: a node in a
scratch project (openwrt-prep, opnsense-prep) with its WAN on a NAT node, then over the
console strongswan-full (OpenWrt) or the firmware update to the newest minor release
(OPNsense), a poweroff, and prepare_template.py to turn the disk into the lab's template.

Downloads are cached in ~/.cache/tunnelmatch-gns3. Python 3.9+ standard library only.
"""

import argparse
import bz2
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run import RESULTS, Console, Gns3, OpnSense, log  # noqa: E402

CACHE = os.path.join(os.path.expanduser("~"), ".cache", "tunnelmatch-gns3")
CHECK_PROJECT = "tmlab-template-check"
UA = {"User-Agent": "tunnelmatch-lab"}


def fetch(url, timeout=60):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def download(url, dst):
    """Download to dst (kept as a cache; a finished file is reused)."""
    if os.path.exists(dst):
        log(f"  cached {dst}")
        return dst
    log(f"  downloading {url}")
    tmp = dst + ".part"
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    os.replace(tmp, dst)
    return dst


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify(path, expected):
    got = sha256(path)
    if got != expected.lower():
        os.remove(path)  # a bad download must not stay in the cache
        sys.exit(f"SHA-256 mismatch for {path}: expected {expected}, got {got}. Removed it; run again.")
    log(f"  SHA-256 ok ({got[:16]}…)")


def gunzip(src, dst):
    """Gunzip, ignoring what follows the gzip stream (OpenWrt images are padded: gzip's 'trailing garbage')."""
    d = zlib.decompressobj(wbits=31)
    with open(src, "rb") as f, open(dst + ".part", "wb") as out:
        for block in iter(lambda: f.read(1 << 20), b""):
            out.write(d.decompress(block))
            if d.eof:
                break
        out.write(d.flush())
    os.replace(dst + ".part", dst)


# --------------------------------------------------------------------------- appliances


def get_mikrotik(folder):
    version = fetch("https://upgrade.mikrotik.com/routeros/NEWESTa7.stable").decode().split()[0]
    base = f"https://download.mikrotik.com/routeros/{version}"
    image = f"chr-{version}.img"
    zipped = download(f"{base}/{image}.zip", os.path.join(folder, image + ".zip"))
    verify(zipped, fetch(f"{base}/{image}.zip.sha256").decode().split()[0])
    out = os.path.join(folder, image)
    if not os.path.exists(out):
        with zipfile.ZipFile(zipped) as z:
            member = next(n for n in z.namelist() if n.endswith(".img"))
            with z.open(member) as src, open(out + ".part", "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
        os.replace(out + ".part", out)
    return version, out


def get_vyos(folder):
    rel = json.loads(fetch("https://api.github.com/repos/vyos/vyos-nightly-build/releases/latest"))
    asset = next(a for a in rel["assets"] if a["name"].endswith("-generic-amd64.iso"))
    iso = download(asset["browser_download_url"], os.path.join(folder, asset["name"]))
    digest = asset.get("digest") or ""
    if digest.startswith("sha256:"):
        verify(iso, digest.split(":", 1)[1])
    else:
        log("  no SHA-256 published for this asset; not verified")
    return rel["tag_name"], iso


def get_openwrt(folder):
    version = json.loads(fetch("https://downloads.openwrt.org/.versions.json"))["stable_version"]
    base = f"https://downloads.openwrt.org/releases/{version}/targets/x86/64"
    name = f"openwrt-{version}-x86-64-generic-ext4-combined.img"
    gz = download(f"{base}/{name}.gz", os.path.join(folder, name + ".gz"))
    rows = (line.split(None, 1) for line in fetch(f"{base}/sha256sums").decode().splitlines() if line.strip())
    sums = {f.strip().lstrip("*"): h for h, f in rows}  # "<hash> *<file>"
    verify(gz, sums[name + ".gz"])
    out = os.path.join(folder, name)
    if not os.path.exists(out):
        gunzip(gz, out)
    return version, out


def get_opnsense(folder):
    listing = fetch("https://pkg.opnsense.org/releases/").decode()
    version = max(set(re.findall(r'href="(\d+\.\d+)/"', listing)), key=lambda v: tuple(map(int, v.split("."))))
    base = f"https://pkg.opnsense.org/releases/{version}"
    name = f"OPNsense-{version}-nano-amd64.img"
    bz = download(f"{base}/{name}.bz2", os.path.join(folder, name + ".bz2"))
    sums = fetch(f"{base}/OPNsense-{version}-checksums-amd64.sha256").decode()
    verify(bz, re.search(r"SHA256 \(" + re.escape(name + ".bz2") + r"\) = (\w+)", sums).group(1))
    out = os.path.join(folder, name)
    if not os.path.exists(out):
        with bz2.open(bz) as src, open(out + ".part", "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 20)
        os.replace(out + ".part", out)
    return version, out


def qemu_path(g):
    for t in g.templates():
        if t["template_type"] == "qemu" and t.get("qemu_path"):
            return t["qemu_path"]
    return "/usr/bin/qemu-system-x86_64"


def create_template(g, name, image, spec, compute_id, replace):
    existing = g.template(name)
    if existing and not replace:
        log(f"  template '{name}' exists; skipped (--replace to recreate)")
        return existing, False
    tpl = {
        "name": name, "template_type": "qemu", "compute_id": compute_id, "qemu_path": qemu_path(g),
        "platform": "", "adapter_type": "virtio-net-pci", "console_type": "telnet", "boot_priority": "c",
        "hda_disk_image": "", "cdrom_image": "", "linked_clone": True, "on_close": "power_off",
        "options": "", "default_name_format": "{name}-{0}",
    }
    tpl.update(spec["template"])
    tpl["hda_disk_image" if spec["media"] == "disk" else "cdrom_image"] = image
    if existing:
        g.api("DELETE", f"/templates/{existing['template_id']}")
    t = g.api("POST", "/templates", tpl)
    log(f"  template '{name}' created ({t['ram']} MB, {t['cpus']} vCPU, {t['adapters']} x {t['adapter_type']}, console {t['console_type']})")
    return t, True


def boot_node(g, project_name, template, compute_id):
    """A fresh scratch project with one node of the template, started. Returns (project_id, node)."""
    pid = g.create_project(project_name)["project_id"]
    node = g.add_node(pid, template["template_id"], "check", 0, 0, compute_id)
    g.api("POST", f"/projects/{pid}/nodes/{node['node_id']}/start")
    return pid, node


def kvm_in_use(node):
    """True if the node's QEMU process runs with KVM (GNS3 adds -enable-kvm when the server has it)."""
    out = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
    return any("-enable-kvm" in line or "accel=kvm" in line for line in out.splitlines() if node["node_id"] in line)


def check_login(g, template, pattern, compute_id, timeout=600, keep=False):
    """Boot one node of the template and wait for its login prompt on the telnet console."""
    log(f"  booting a test node of '{template['name']}' in project {CHECK_PROJECT}")
    pid, node = boot_node(g, CHECK_PROJECT, template, compute_id)
    host, port, _ = g.console(pid, node["node_id"])
    logfile = os.path.join(RESULTS, "template-" + re.sub(r"[^a-z0-9]+", "-", template["name"].lower()).strip("-") + ".log")
    os.makedirs(RESULTS, exist_ok=True)
    if os.path.exists(logfile):
        os.remove(logfile)
    time.sleep(2)
    con = Console(host, port, logfile)
    ok = False
    try:
        end = time.time() + timeout
        while time.time() < end and not ok:
            try:
                con.expect([pattern], 20)
                ok = True
            except TimeoutError:
                con.sendline()
        kvm = kvm_in_use(node)
    finally:
        con.close()
        if not keep:
            g.api("DELETE", f"/projects/{pid}")
    log(f"  console: {'login prompt seen' if ok else 'NO login prompt within %d s' % timeout} · KVM: {'yes' if kvm else 'NOT in use'} · log {logfile}")
    return ok


# --------------------------------------------------------------------------- preparation


def run_cmd(con, cmd, timeout=60):
    con.sendline(cmd)
    return con.expect([r"^TMLAB# $"], timeout)[2]


def wait_online(con, check, logfile, tries=30):
    """Wait for a DHCP lease and DNS through the NAT node; `check` is a shell test that succeeds online."""
    for _ in range(tries):
        if "TMLAB-NET-OK" in run_cmd(con, f"{check} >/dev/null 2>&1 && echo TMLAB-NET-OK", 30):
            return
        time.sleep(5)
    sys.exit(f"No internet through the NAT node; see {logfile}")


def openwrt_shell(con, logfile):
    end = time.time() + 300
    while True:
        con.sendline()
        try:
            con.expect([r"^root@[^\n]*# ?$"], 15)
            break
        except TimeoutError:
            if time.time() > end:
                sys.exit(f"OpenWrt gave no shell prompt; see {logfile}")
    con.drain(2)
    con.sendline("PS1='TMLAB# '; export PS1")
    con.expect([r"^TMLAB# $"], 30)


def prepare_openwrt_node(con, logfile):
    openwrt_shell(con, logfile)
    wait_online(con, "nslookup downloads.openwrt.org", logfile)
    # strongswan-full does not pull in seqiv, which the kernel needs for AES-GCM ESP SAs
    pkgs = "strongswan-full kmod-crypto-seqiv"
    pm = f"apk update && apk add {pkgs}" if "apk" in run_cmd(con, "command -v apk opkg") else f"opkg update && opkg install {pkgs}"
    if "TMLAB-EXIT=0" not in run_cmd(con, pm + "; echo TMLAB-EXIT=$?", 900):
        sys.exit(f"Installing strongswan-full failed; see {logfile}")
    if "TMLAB-OK" not in run_cmd(con, "command -v swanctl >/dev/null && echo TMLAB-OK"):
        sys.exit(f"swanctl is missing after the install; see {logfile}")
    run_cmd(con, "sync")
    con.sendline("poweroff")


def prepare_opnsense_node(con, logfile):
    """Firmware update to the newest minor release the way the GUI runs it (scripts/firmware/update.sh):
    packages, then base and kernel with a reboot, until nothing is pending."""
    fw = OpnSense({"password": "opnsense"}, None, con)
    for _ in range(3):
        fw.login(900)
        wait_online(con, "drill pkg.opnsense.org | grep -q 'ANSWER: [1-9]'", logfile)
        if "TMLAB-EXIT=0" not in run_cmd(con, "opnsense-update -pt opnsense > /tmp/tmlab-update.log 2>&1; echo TMLAB-EXIT=$?", 1800):
            sys.exit(f"OPNsense package update failed; see {logfile} and /tmp/tmlab-update.log on the node")
        if "BK-PENDING=0" not in run_cmd(con, "opnsense-update -bk -c; echo BK-PENDING=$?", 300):
            break
        if "TMLAB-EXIT=0" not in run_cmd(con, "opnsense-update -bk > /tmp/tmlab-update.log 2>&1; echo TMLAB-EXIT=$?", 1800):
            sys.exit(f"OPNsense base/kernel update failed; see {logfile}")
        con.sendline("/usr/local/etc/rc.reboot")
        con.expect([r"Rebooting|cpu_reset"], 300)  # so the next login does not see the old shell
    else:
        sys.exit(f"OPNsense still had updates pending after three rounds; see {logfile}")
    log("  " + run_cmd(con, "opnsense-version").splitlines()[1].strip())
    # the NAT node's lease must not go into the template: in the lab, dhclient finds no DHCP
    # server, falls back to the saved lease and replaces the static WAN address with it
    run_cmd(con, "rm -f /var/db/dhclient.leases.*; sync")
    con.sendline("/usr/local/etc/rc.halt")  # powers off; QEMU exits


def prepare(g, base, name, spec, compute_id, cfg_path, replace):
    """One-time preparation with internet access: a node of the base template in a scratch
    project with its WAN on a NAT node, the appliance's steps over the console (ending in a
    poweroff), then prepare_template.py turns the disk into the lab's template."""
    if g.template(name) and not replace:
        log(f"  template '{name}' exists; skipped (--replace to recreate)")
        return True
    project, node_name = spec["prep_project"], spec["prep_node"]
    log(f"  preparing {node_name} in project {project} ({spec['prep_what']})")
    pid = g.create_project(project)["project_id"]
    node = g.add_node(pid, base["template_id"], node_name, 0, 0, compute_id)
    nat = g.add_node(pid, g.template(ttype="nat")["template_id"], "NAT", 200, 0, compute_id)
    g.add_link(pid, (node["node_id"], spec["wan_adapter"], 0), (nat["node_id"], 0, 0))
    g.api("POST", f"/projects/{pid}/nodes/{nat['node_id']}/start")
    g.api("POST", f"/projects/{pid}/nodes/{node['node_id']}/start")
    host, port, _ = g.console(pid, node["node_id"])
    os.makedirs(RESULTS, exist_ok=True)
    logfile = os.path.join(RESULTS, f"{project}.log")
    if os.path.exists(logfile):
        os.remove(logfile)
    time.sleep(2)
    con = Console(host, port, logfile)
    try:
        spec["prepare"](con, logfile)
    finally:
        con.close()
    for _ in range(spec.get("poweroff_wait", 60)):  # QEMU exits after poweroff and GNS3 marks the node stopped
        time.sleep(5)
        if g.api("GET", f"/projects/{pid}/nodes/{node['node_id']}")["status"] == "stopped":
            break
    else:
        g.api("POST", f"/projects/{pid}/nodes/{node['node_id']}/stop")
    g.api("POST", f"/projects/{pid}/nodes/{nat['node_id']}/stop")
    cmd = [sys.executable, os.path.join(HERE, "prepare_template.py"), "--config", cfg_path,
           "--project", project, "--node", node_name, "--name", name]
    if subprocess.run(cmd + (["--replace"] if replace else [])).returncode != 0:
        return False
    g.api("DELETE", f"/projects/{pid}")  # its disk is in the template now; frees the space
    return True


# Template settings per appliance; "disk" or "cdrom" says where the image goes.
APPLIANCES = {
    "mikrotik": {
        "get": get_mikrotik, "packed": True, "media": "disk", "login": r"Login: ?$",
        "template": {"ram": 384, "cpus": 1, "adapters": 4, "hda_disk_interface": "virtio",
                     "port_name_format": "ether{port1}", "category": "router", "symbol": ":/symbols/classic/router.svg"},
    },
    "vyos": {
        "get": get_vyos, "media": "cdrom", "login": r"vyos login: ?$",
        "template": {"ram": 2048, "cpus": 2, "adapters": 3, "boot_priority": "d",
                     "port_name_format": "eth{0}", "category": "router", "symbol": ":/symbols/classic/router.svg"},
    },
    "openwrt": {
        "get": get_openwrt, "packed": True, "media": "disk", "login": r"activate this console|login: ?$|^root@[^\n]*# ?$", "base": "OpenWrt",
        "prepare": prepare_openwrt_node, "prep_project": "openwrt-prep", "prep_node": "openwrt", "wan_adapter": 1,
        "prep_what": "eth1 → NAT, strongswan-full",
        "template": {"ram": 256, "cpus": 1, "adapters": 2, "hda_disk_interface": "virtio",
                     "port_name_format": "eth{0}", "category": "router", "symbol": ":/symbols/classic/router.svg"},
    },
    "opnsense": {
        "get": get_opnsense, "packed": True, "media": "disk", "login": r"login: ?$", "base": "OPNsense",
        "prepare": prepare_opnsense_node, "prep_project": "opnsense-prep", "prep_node": "opnsense", "wan_adapter": 1,
        "prep_what": "vtnet1 → NAT, firmware update", "poweroff_wait": 120,
        "template": {"ram": 2048, "cpus": 1, "adapters": 4, "hda_disk_interface": "virtio",
                     "port_name_format": "vtnet{0}", "category": "firewall", "symbol": ":/symbols/classic/firewall.svg"},
    },
}


# --------------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None, help="lab config for the server login and template names (default lab/gns3/lab.json)")
    ap.add_argument("--only", default=",".join(APPLIANCES), help="comma-separated: " + ", ".join(APPLIANCES))
    ap.add_argument("--replace", action="store_true", help="re-upload images and recreate templates that already exist")
    ap.add_argument("--no-check", action="store_true", help="do not boot new templates to check the console")
    ap.add_argument("--no-prepare", action="store_true", help="OpenWrt, OPNsense: create the base template only")
    opt = ap.parse_args()

    cfg_path = opt.config or next(p for p in (os.path.join(HERE, "lab.json"), os.path.join(HERE, "lab.example.json")) if os.path.exists(p))
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    with open(os.path.join(HERE, "lab.example.json"), encoding="utf-8") as f:
        example = json.load(f)["nodes"]
    srv = cfg["server"]
    compute_id = srv.get("compute_id", "local")
    g = Gns3(srv["url"], srv.get("user"), srv.get("password"))
    log(f"GNS3 {g.version} at {g.url} (API {g.v})")

    failed = []
    for key in [k.strip() for k in opt.only.split(",") if k.strip()]:
        if key not in APPLIANCES:
            sys.exit(f"Unknown appliance '{key}'; choose from {', '.join(APPLIANCES)}.")
        spec = APPLIANCES[key]
        name = (cfg.get("nodes", {}).get(key) or example[key])["template"]
        base_name = spec.get("base", name)  # OpenWrt: the lab uses the prepared template
        log(f"{key}: template '{base_name}'" + (f", then '{name}'" if base_name != name else ""))
        if g.template(base_name) and (base_name == name or g.template(name)) and not opt.replace:
            log("  all templates exist; skipped (--replace to recreate)")
            continue
        folder = os.path.join(CACHE, key)
        os.makedirs(folder, exist_ok=True)
        version, path = spec["get"](folder)
        image = os.path.basename(path)
        log(f"  version {version}, image {image}")
        if image in g.images() and not opt.replace:
            log("  image already on the server")
        else:
            log("  uploading to the server")
            g.upload_image(image, path)
        if spec.get("packed"):
            os.remove(path)  # unpacked copy: on the server now, and the archive stays in the cache
        t, new = create_template(g, base_name, image, spec, compute_id, opt.replace)
        if new and not opt.no_check and not check_login(g, t, spec["login"], compute_id):
            failed.append(f"{base_name}: no login prompt on the telnet console")
            continue
        if base_name != name and not opt.no_prepare:
            if not prepare(g, t, name, spec, compute_id, cfg_path, opt.replace):
                failed.append(f"{name}: preparation failed")
    if failed:
        sys.exit("Failed:\n  " + "\n  ".join(failed))
    log("Done. Check with: python3 lab/gns3/run.py --dry-run")


if __name__ == "__main__":
    main()
