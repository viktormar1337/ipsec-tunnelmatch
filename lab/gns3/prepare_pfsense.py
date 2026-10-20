#!/usr/bin/env python3
"""
One-time step for pfSense in the GNS3 lab: turns a pfSense you installed by hand into
a template the lab can boot directly.

The GNS3 pfSense appliance is an installer ISO with a VNC console. Install it once in a
scratch project (see lab/gns3/README.md, "pfSense"), shut it down, then run this on the
GNS3 server machine:

    python3 lab/gns3/prepare_pfsense.py --project pfsense-prep

It copies the node's installed disk into the GNS3 images folder as a standalone image
and creates the template "pfSense 2.7.2 (tmlab)": same settings as the template you
installed from, but booting that disk, no ISO, and a telnet (serial) console.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run import Gns3  # noqa: E402

DROP = {"template_id", "builtin", "usage"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None, help="lab config for the server login (default lab/gns3/lab.json)")
    ap.add_argument("--project", default="pfsense-prep", help="GNS3 project with the installed pfSense node")
    ap.add_argument("--node", default=None, help="node name (default: the only QEMU node in the project)")
    ap.add_argument("--name", default="pfSense 2.7.2 (tmlab)", help="name of the template to create")
    ap.add_argument("--images-dir", default=None, help="GNS3 QEMU images folder (default: next to the projects folder)")
    ap.add_argument("--replace", action="store_true", help="replace an existing template and image with the same name")
    opt = ap.parse_args()

    cfg_path = opt.config or next(p for p in (os.path.join(HERE, "lab.json"), os.path.join(HERE, "lab.example.json")) if os.path.exists(p))
    with open(cfg_path, encoding="utf-8") as f:
        srv = json.load(f)["server"]
    g = Gns3(srv["url"], srv.get("user"), srv.get("password"))

    project = g.project_by_name(opt.project)
    if not project:
        sys.exit(f"No GNS3 project named '{opt.project}'. Install pfSense in a project with that name, or pass --project.")
    pid = project["project_id"]
    if project.get("status") != "opened":
        g.open_project(pid)
        project = g.api("GET", f"/projects/{pid}")
    nodes = [n for n in g.nodes(pid) if n["node_type"] == "qemu" and (not opt.node or n["name"] == opt.node)]
    if len(nodes) != 1:
        sys.exit(f"Expected one QEMU node{' named ' + opt.node if opt.node else ''} in '{opt.project}', found {len(nodes)}: "
                 + ", ".join(n["name"] for n in nodes) + ". Use --node.")
    node = nodes[0]
    if node["status"] != "stopped":
        sys.exit(f"Node '{node['name']}' is {node['status']}. Shut pfSense down first (console menu option 6, Halt) and stop the node.")

    disk = os.path.join(project["path"], "project-files", "qemu", node["node_id"], "hda_disk.qcow2")
    if not os.path.exists(disk):
        sys.exit(f"Installed disk not found at {disk}. Run this on the GNS3 server machine, after pfSense was installed and started at least once.")
    images = opt.images_dir or os.path.join(os.path.dirname(os.path.dirname(project["path"])), "images", "QEMU")
    if not os.path.isdir(images):
        sys.exit(f"Images folder {images} not found; pass --images-dir.")
    image = re.sub(r"[^a-z0-9]+", "-", opt.name.lower()).strip("-") + ".qcow2"  # pfsense-2-7-2-tmlab.qcow2
    dst = os.path.join(images, image)

    existing = g.template(opt.name)
    if (existing or os.path.exists(dst)) and not opt.replace:
        sys.exit(f"Template '{opt.name}' or image {dst} already exists; pass --replace to overwrite.")

    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        sys.exit("qemu-img not found (apt install qemu-utils).")
    print(f"Copying the installed disk to {dst}")
    subprocess.run([qemu_img, "convert", "-O", "qcow2", disk, dst], check=True)
    st = os.stat(images)
    try:
        os.chown(dst, st.st_uid, st.st_gid)  # the GNS3 server user must own it
    except PermissionError:
        print(f"Note: could not change the owner of {dst}; make sure the GNS3 server user can read it.")

    source = g.api("GET", f"/templates/{node['template_id']}") if node.get("template_id") else {}
    tpl = {k: v for k, v in source.items() if k not in DROP}
    tpl.update({
        "name": opt.name,
        "template_type": "qemu",
        "compute_id": node.get("compute_id", "local"),
        "hda_disk_image": image,
        "cdrom_image": "",
        "boot_priority": "c",
        "console_type": "telnet",
        "linked_clone": True,
    })
    for k in ("adapters", "adapter_type", "ram", "cpus", "hda_disk_interface", "qemu_path", "platform"):
        if k in node.get("properties", {}) and k not in tpl:
            tpl[k] = node["properties"][k]
    if existing:
        g.api("DELETE", f"/templates/{existing['template_id']}")
    t = g.api("POST", "/templates", tpl)
    print(f"Template '{t['name']}' created ({t.get('adapters', '?')} x {t.get('adapter_type', '?')}, console {t.get('console_type')}).")
    print("Set nodes.pfsense.template in lab/gns3/lab.json to this name. You can delete the prep project now.")


if __name__ == "__main__":
    main()
