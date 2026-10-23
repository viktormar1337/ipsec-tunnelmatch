#!/usr/bin/env node
/*
 * IPsec Tunnelmatch GNS3 lab: builds the test plan.
 *
 * For every pair of enabled nodes (full mesh) it picks a profile, runs the tool's own
 * checks and generators for both sides, and merges each node's tunnels into one
 * config. run.py then pushes the configs over the GNS3 consoles and verifies them.
 *
 *   node lab/gns3/generate.js [--config lab/gns3/lab.json] [--profile strongest|recommended|minimum] [--lans 2]
 *
 * --lans N gives every node N local networks (its "lan" plus 10.x.100.0/24, 10.x.200.0/24 in
 * the same layout), so each tunnel carries N x N subnet pairs.
 *
 * Output (lab/gns3/out/, git-ignored because it holds the lab's pre-shared keys):
 *   plan.json        everything run.py needs
 *   <node>.txt       the merged config per node, for pasting by hand
 *
 * All sides run policy-based, so every platform can talk to every other one and the
 * generated selectors are what gets tested.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { loadTool } = require("../tm.js");
const { BASE, RECOMMENDED, MINIMUM } = require("../scenarios.js");

const TM = loadTool();
const HERE = __dirname;
const SIDES = ["A", "B"];

/* Lab node kinds and the tool vendor each one runs. */
const KINDS = {
  iosxe: { vendor: "iosxe", name: "IOSXE" },
  asa: { vendor: "asa", name: "ASA" },
  opnsense: { vendor: "opnsense", name: "OPNSENSE" },
  pfsense: { vendor: "opnsense", name: "PFSENSE" }, // the tool's OPNsense/pfSense platform, pfSense block
  strongswan: { vendor: "strongswan", name: "STRONGSWAN" },
  mikrotik: { vendor: "mikrotik", name: "MIKROTIK" },
  vsrx: { vendor: "juniper", name: "VSRX" },
  vyos: { vendor: "vyos", name: "VYOS" },
  openwrt: { vendor: "openwrt", name: "OPENWRT" },
  panos: { vendor: "paloalto", name: "PANOS" },
};

/* What the devices report, normalised the same way run.py normalises their output. */
const NORM = {
  enc: { aes128: "AES-CBC-128", aes192: "AES-CBC-192", aes256: "AES-CBC-256", aes128gcm: "AES-GCM-128", aes256gcm: "AES-GCM-256", "3des": "3DES" },
  int: { sha1: "SHA1", sha256: "SHA256", sha384: "SHA384", sha512: "SHA512", md5: "MD5" },
};

function args() {
  const a = process.argv.slice(2);
  const get = (flag, def) => { const i = a.indexOf(flag); return i >= 0 ? a[i + 1] : def; };
  const cfgPath = get("--config", fs.existsSync(path.join(HERE, "lab.json")) ? path.join(HERE, "lab.json") : path.join(HERE, "lab.example.json"));
  const cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  const lans = Number(get("--lans", 1));
  if (!(lans >= 1 && lans <= 3)) throw new Error(`--lans must be 1, 2 or 3 (got ${get("--lans")})`);
  return { cfg, cfgPath, profile: get("--profile", cfg.profile || "strongest"), out: get("--out", path.join(HERE, "out")), lans };
}

/* The node's networks: its "lan", then the same addresses with the third octet 100, 200. */
function lansOf(n, count) {
  const third = (addr, k) => addr.replace(/^(\d+\.\d+)\.\d+\./, `$1.${100 * k}.`);
  // lan_host: a host on the LAN interface (PAN-OS) that pings instead of the device itself
  const out = [{ net: n.lan, ip: n.lan_ip, ping: n.lan_host || n.lan_ip }];
  for (let k = 1; k < count; k++) {
    const net = third(n.lan, k);
    if (!TM.parseCidr(net) || +n.lan.split("/")[1] < 24) throw new Error(`--lans: cannot derive a second network from ${n.lan} (needs a /24 or smaller)`);
    out.push({ net, ip: third(n.lan_ip, k), ping: third(n.lan_ip, k) });
  }
  return out;
}

/* A tool state for one tunnel between two lab nodes. */
function stateFor(cfg, a, b, crypto_) {
  const order = Object.keys(KINDS);
  const side = (id, other) => {
    const n = cfg.nodes[id];
    const v = TM.vendor(KINDS[id].vendor);
    return Object.assign({}, v.defaults, {
      name: KINDS[id].name,
      vendor: KINDS[id].vendor,
      ip: n.wan_ip,
      nets: n.lans.map((l) => l.net).join("\n"),
      // policy-based wherever the platform has it; Junos is route-based only (st0 + traffic selectors)
      mode: v.modes.includes("policy") ? "policy" : v.modes[0],
    }, id === "asa" ? { iface: "outside" } : {}, id === "iosxe" || id === "vyos" ? { iface: n.wan_if } : {},
    // one st0 unit per peer on Junos
    id === "vsrx" ? { iface: `${n.wan_if}.0`, tun: `st0.${order.indexOf(other) + 1}` } : {},
    // and one tunnel unit per peer on PAN-OS
    id === "panos" ? { iface: n.wan_if, tun: `tunnel.${order.indexOf(other) + 1}` } : {});
  };
  const s = JSON.parse(JSON.stringify(Object.assign({}, BASE, { tunnelName: `${KINDS[a].name}-${KINDS[b].name}` }, crypto_ || {})));
  s.A = side(a, b);
  s.B = side(b, a);
  return s;
}

function pickProfile(cfg, a, b, which) {
  if (which === "recommended") return Object.assign({}, RECOMMENDED);
  if (which === "minimum") return Object.assign({}, MINIMUM);
  if (which !== "strongest") throw new Error(`Unknown profile "${which}" (strongest, recommended, minimum)`);
  return TM.baseline.strongestProfile(stateFor(cfg, a, b, MINIMUM));
}

const profileLabel = (p) =>
  `${TM.encLabel(p.p1enc)} / ${TM.intLabel(p.p1int)} / group ${p.dh} · ESP ${TM.encLabel(p.p2enc)}` +
  (TM.isGcm(p.p2enc) ? "" : " / " + TM.intLabel(p.p2int)) + ` · PFS ${p.pfs || "off"}`;

function expectFor(p) {
  const g1 = TM.isGcm(p.p1enc), g2 = TM.isGcm(p.p2enc);
  return {
    ike: { encr: NORM.enc[p.p1enc], prf: NORM.int[p.p1int], integ: g1 ? null : NORM.int[p.p1int], dh: p.dh },
    esp: { encr: NORM.enc[p.p2enc], integ: g2 ? null : NORM.int[p.p2int], pfs: p.pfs || 0 },
  };
}

/* Runs the tool for one side and returns its config text (all blocks joined). */
function toolConfig(S, k) {
  const R = TM.analyze(S);
  const out = TM.vendor(S[k].vendor).generate(TM.contextFor(S, k, R));
  return Array.isArray(out) ? out : [{ title: TM.vendor(S[k].vendor).label, text: out }];
}

/* ---------- per-platform merging of several tunnels into one device config ---------- */

function mergeIosxe(node, tunnels) {
  const proposals = [];
  const body = tunnels.map((t, i) => {
    let text = t.text.replace(/<PSK>/g, t.psk);
    // one IKEv2 policy for the whole router (IOS-XE does not choose a policy per peer)
    text = text.replace(/crypto ikev2 policy (\S+)\n proposal (\S+)\n(?: !.*\n)*!\n/, (m, pol, prop) => { proposals.push(prop); return ""; });
    // one crypto map entry per peer
    text = text.replace(/crypto map CMAP 10 ipsec-isakmp/g, `crypto map CMAP ${10 * (i + 1)} ipsec-isakmp`);
    return text;
  });
  const lines = [
    `hostname TM-IOSXE`,
    ...(node.extra_config || []),
    `interface ${node.wan_if}`, ` ip address ${node.wan_ip} ${mask(node.wan_ip, node.prefix)}`, ` no shutdown`, `!`,
    ...node.lans.flatMap((l, i) => [`interface Loopback${i + 1}`, ` ip address ${l.ip} ${maskOf(l.net)}`, `!`]),
    ...node.routes.map((r) => `ip route ${r.net} ${r.mask} ${r.via}`),
    ...body.join("\n!\n").split("\n"),
    `crypto ikev2 policy POL-TMLAB`,
    ...proposals.map((p) => ` proposal ${p}`),
    `!`,
  ];
  return { lines: clean(lines) };
}

function mergeAsa(node, tunnels) {
  if (node.lans.length > 1) throw new Error("ASA: --lans needs a second inside interface per network; not supported in the lab");
  const body = tunnels.map((t, i) => t.text
    .replace(/<PSK>/g, t.psk)
    .replace(/crypto ikev2 policy 10\b/g, `crypto ikev2 policy ${10 * (i + 1)}`)
    .replace(/crypto map (\S+) 10 /g, `crypto map $1 ${10 * (i + 1)} `));
  const lines = [
    `hostname TM-ASA`,
    ...(node.extra_config || []),
    `interface ${node.wan_if}`, ` nameif outside`, ` security-level 0`, ` ip address ${node.wan_ip} ${mask(node.wan_ip, node.prefix)}`, ` no shutdown`, `!`,
    `interface ${node.lan_if}`, ` nameif inside`, ` security-level 100`, ` ip address ${node.lan_ip} ${maskOf(node.lan)}`, ` no shutdown`, `!`,
    `management-access inside`,
    `icmp permit any outside`,
    ...node.routes.map((r) => `route outside ${r.net} ${r.mask} ${r.via}`),
    ...body.join("\n!\n").split("\n"),
  ];
  return { lines: clean(lines) };
}

/* OPNsense: the tool writes GUI field values; read them back into model fields. */
function parseOpnsense(text) {
  const conn = { children: [] };
  let where = "conn", child = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s{2,}\([^)]*\)\s*$/, ""); // drop "(remove the default first)" and similar
    if (/^\s*Local authentication/.test(line)) { where = "local"; continue; }
    if (/^\s*Remote authentication/.test(line)) { where = "remote"; continue; }
    if (/^\s*Child \d+/.test(line)) { child = {}; conn.children.push(child); where = "child"; continue; }
    if (/^\d+\. /.test(line)) { where = /^\d+\. Connection /.test(line) ? "conn" : "other"; continue; }
    const m = line.match(/^\s+([A-Za-z][A-Za-z ()]*?) \.{2,} (.+?)\s*$/);
    if (!m) continue;
    const [, key, value] = m;
    const tgt = where === "child" ? child : where === "conn" ? conn : where === "local" ? (conn.local = conn.local || {}) : where === "remote" ? (conn.remote = conn.remote || {}) : null;
    if (tgt) tgt[key] = value;
  }
  return conn;
}

function mergeOpnsense(node, tunnels) {
  const connections = tunnels.map((t) => {
    const block = t.blocks.find((b) => /OPNsense/.test(b.title));
    const c = parseOpnsense(block.text);
    const need = (o, k) => { if (!o || o[k] === undefined) throw new Error(`OPNsense output for ${t.peer}: field "${k}" not found`); return o[k]; };
    return {
      description: `tmlab ${t.peer}`,
      proposals: need(c, "Proposals"),
      local_addrs: need(c, "Local addresses"),
      remote_addrs: need(c, "Remote addresses"),
      unique: need(c, "Unique").toLowerCase(),
      dpd_delay: need(c, "DPD delay (s)"),
      rekey_time: need(c, "Rekey time (s)"),
      local_id: need(c.local, "Id"),
      remote_id: need(c.remote, "Id"),
      psk: t.psk,
      children: c.children.map((ch) => ({
        local_ts: need(ch, "Local"),
        remote_ts: need(ch, "Remote"),
        esp_proposals: need(ch, "ESP proposals"),
        start_action: need(ch, "Start action").toLowerCase(),
        rekey_time: need(ch, "Rekey time (s)"),
        policies: /^checked/.test(need(ch, "Policies")) ? "1" : "0",
      })),
    };
  });
  return {
    data: {
      wan_if: node.wan_if, wan_ip: node.wan_ip, wan_prefix: node.prefix,
      lan_if: node.lan_if, lan_ip: node.lan_ip, lan_prefix: Number(node.lan.split("/")[1]),
      connections,
    },
    shell: [...extraLans(node).map((l) => `ifconfig ${node.lan_if} inet ${l.ip}/${l.net.split("/")[1]} alias`),
      ...node.routes.map((r) => `route add -net ${r.cidr} ${r.via}`)],
  };
}

/* pfSense: the tool writes Tunnels GUI field values; map them to config.xml values. */
function parsePfsense(text) {
  const out = { p1: {}, p2: [] };
  let cur = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\s{2,}\([^)]*\)\s*$/, "");
    if (/^Phase 1\s*$/.test(line)) { cur = out.p1; continue; }
    if (/^Phase 2 #\d+/.test(line)) { cur = {}; out.p2.push(cur); continue; }
    const m = line.match(/^\s+([A-Za-z][A-Za-z -]*?) \.{2,} (.+?)\s*$/);
    if (m && cur) cur[m[1]] = m[2];
  }
  return out;
}

function mergePfsense(node, tunnels) {
  const map = TM.vendor("opnsense").pfsenseConfig;
  const conns = tunnels.map((t) => {
    const block = t.blocks.find((b) => /pfSense/.test(b.title));
    const c = parsePfsense(block.text);
    const need = (o, k, table) => {
      const v = o[k];
      if (v === undefined) throw new Error(`pfSense output for ${t.peer}: field "${k}" not found`);
      if (table && table[v] === undefined) throw new Error(`pfSense output for ${t.peer}: unknown ${k} "${v}"`);
      return table ? table[v] : v;
    };
    const dpd = need(c.p1, "Dead Peer Detection").match(/delay (\d+) s, max failures (\d+)/);
    const cidr = (v) => { const [address, netbits] = v.split("/"); return { type: "network", address, netbits }; };
    return {
      descr: `tmlab ${t.peer}`,
      remote: need(c.p1, "Remote gateway"),
      psk: t.psk,
      enc: need(c.p1, "Encryption", map.enc),
      hash: need(c.p1, "Hash", map.int1),
      dhgroup: String(parseInt(need(c.p1, "DH key group"), 10)),
      rekey_time: need(c.p1, "Rekey Time"),
      lifetime: need(c.p1, "Life Time"),
      dpd_delay: dpd[1],
      dpd_maxfail: dpd[2],
      phase2: c.p2.map((p) => {
        const hash = need(p, "Hash");
        const pfs = need(p, "PFS key group");
        return {
          localid: cidr(need(p, "Local network")),
          remoteid: cidr(need(p, "Remote network")),
          enc: need(p, "Encryption", map.enc),
          hash: /^\(none/.test(hash) ? null : need(p, "Hash", map.int2),
          pfsgroup: pfs === "off" ? "0" : String(parseInt(pfs, 10)),
          rekey_time: need(p, "Rekey Time"),
          lifetime: need(p, "Life Time"),
        };
      }),
    };
  });
  return {
    data: {
      wan_if: node.wan_if, wan_ip: node.wan_ip, wan_prefix: node.prefix,
      lan_if: node.lan_if, lan_ip: node.lan_ip, lan_prefix: Number(node.lan.split("/")[1]),
      tunnels: conns,
    },
    shell: [...extraLans(node).map((l) => `ifconfig ${node.lan_if} inet ${l.ip}/${l.net.split("/")[1]} alias`),
      ...node.routes.map((r) => `route add -net ${r.cidr} ${r.via}`)],
  };
}

/* MikroTik: flatten the tool's RouterOS script into one full-path command per line
   ("/ip ipsec profile" + "add ..." -> "/ip ipsec profile add ..."), no comments. */
function routerosCommands(text) {
  const out = [];
  let path = "";
  const joined = text.replace(/\\\n\s*/g, " ");
  for (const raw of joined.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (/^\/[\w /-]+$/.test(line)) { path = line; continue; }
    out.push(line.startsWith("/") ? line : `${path} ${line}`);
  }
  return out;
}

function mergeMikrotik(node, tunnels) {
  const lines = [
    "/system identity set name=TM-MIKROTIK",
    `/ip address add address=${node.wan_ip}/${node.prefix} interface=${node.wan_if}`,
    // the LAN address sits on an empty bridge, RouterOS's usual loopback
    "/interface bridge add name=lan0",
    ...node.lans.map((l) => `/ip address add address=${l.ip}/${l.net.split("/")[1]} interface=lan0`),
    ...node.routes.map((r) => `/ip route add dst-address=${r.cidr} gateway=${r.via}`),
    ...(node.extra_config || []),
    ...tunnels.flatMap((t) => routerosCommands(t.text.replace(/<PSK>/g, t.psk))),
  ];
  return { lines };
}

/* Junos: set commands from the tool, plus the lab's interfaces and zones. The tool output is
   route-based with one traffic selector per subnet pair; auto route insertion adds the routes,
   so no static routes here. */
function mergeVsrx(node, tunnels) {
  const wan = `${node.wan_if}.0`;
  const lines = [
    "set system host-name TM-VSRX",
    `delete interfaces ${node.wan_if}`,
    `set interfaces ${node.wan_if} unit 0 family inet address ${node.wan_ip}/${node.prefix}`,
    ...node.lans.map((l) => `set interfaces lo0 unit 0 family inet address ${l.ip}/${l.net.split("/")[1]}`),
    `set security zones security-zone untrust interfaces ${wan} host-inbound-traffic system-services ike`,
    `set security zones security-zone untrust interfaces ${wan} host-inbound-traffic system-services ping`,
    "set security zones security-zone trust interfaces lo0.0 host-inbound-traffic system-services ping",
    "set security zones security-zone vpn host-inbound-traffic system-services ping",
    ...(node.extra_config || []),
    ...tunnels.flatMap((t) => t.text.replace(/<PSK>/g, t.psk).split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))),
  ];
  return { lines };
}

/* PAN-OS: the factory default config is a virtual wire on ethernet1/1-1/2 with zones trust and
   untrust and rule1; that is removed first. Then the WAN address on ethernet1/1, the LAN on
   ethernet1/2 (lan_if, with a host behind it that pings; PAN-OS 12.2 cannot ping from its own
   address with the legacy virtual router) or else on loopback.1 (/32: the proxy-IDs carry the
   /24), further networks on loopback.2 and up, zones untrust/trust/vpn, an allow-all rule for
   the lab, a management profile that answers ping, and the tool's set commands (route-based,
   one tunnel unit and proxy-IDs per peer, static routes in the default virtual router). */
function mergePanos(node, tunnels) {
  const strip = (l) => l.replace(/\s+#.*$/, "").trim();
  const tool = tunnels.flatMap((t) => t.text.replace(/<PSK>/g, t.psk).split("\n").map(strip).filter((l) => l && !l.startsWith("#")));
  const units = [...new Set(tool.map((l) => (l.match(/^set network interface tunnel units (tunnel\.\d+)/) || [])[1]).filter(Boolean))];
  const loops = node.lans.map((l, i) => ({ unit: `loopback.${i + 1}`, ip: l.ip }));
  const lanEth = node.lan_if ? { unit: node.lan_if, ip: node.lan_ip } : null;
  if (lanEth) loops.shift();
  const trust = [...(lanEth ? [lanEth.unit] : []), ...loops.map((l) => l.unit)];
  const lines = [
    "delete rulebase security rules rule1",
    "delete zone trust",
    "delete zone untrust",
    "delete network virtual-wire default-vwire",
    "delete network interface ethernet ethernet1/1",
    "delete network interface ethernet ethernet1/2",
    "set deviceconfig system hostname TM-PANOS",
    "set network profiles interface-management-profile TM-PING ping yes",
    `set network interface ethernet ${node.wan_if} layer3 ip ${node.wan_ip}/${node.prefix}`,
    `set network interface ethernet ${node.wan_if} layer3 interface-management-profile TM-PING`,
    ...(lanEth ? [`set network interface ethernet ${lanEth.unit} layer3 ip ${lanEth.ip}/${node.lan.split("/")[1]}`,
      `set network interface ethernet ${lanEth.unit} layer3 interface-management-profile TM-PING`] : []),
    ...loops.flatMap((l) => [`set network interface loopback units ${l.unit} ip ${l.ip}/32`,
      `set network interface loopback units ${l.unit} interface-management-profile TM-PING`]),
    ...units.map((u) => `set network interface tunnel units ${u} interface-management-profile TM-PING`),
    `set network virtual-router default interface [ ${[node.wan_if, ...trust, ...units].join(" ")} ]`,
    `set zone untrust network layer3 ${node.wan_if}`,
    `set zone trust network layer3 ${trust.length > 1 ? `[ ${trust.join(" ")} ]` : trust[0]}`,
    ...(units.length ? [`set zone vpn network layer3 [ ${units.join(" ")} ]`] : []),
    "set rulebase security rules TM-LAB from any to any source any destination any application any service any action allow",
    ...(node.extra_config || []),
    ...tool,
  ];
  return { lines };
}

/* VyOS: set commands from the tool (trailing "# ..." notes removed) after the lab's interfaces;
   the LAN address sits on a dummy interface. */
function mergeVyos(node, tunnels) {
  const strip = (l) => l.replace(/\s+#.*$/, "").trim();
  const lines = [
    "set system host-name TM-VYOS",
    `set interfaces ethernet ${node.wan_if} address '${node.wan_ip}/${node.prefix}'`,
    ...node.lans.map((l) => `set interfaces dummy dum0 address '${l.ip}/${l.net.split("/")[1]}'`),
    ...node.routes.map((r) => `set protocols static route ${r.cidr} next-hop ${r.via}`),
    ...(node.extra_config || []),
  ];
  const seen = new Set(lines);
  tunnels.forEach((t) => t.text.replace(/<PSK>/g, t.psk).split("\n").map(strip)
    .filter((l) => l && !l.startsWith("#"))
    .forEach((l) => { if (!seen.has(l)) { seen.add(l); lines.push(l); } }));
  return { lines };
}

/* OpenWrt: network via UCI, then the tool's UCI commands (ipsec, firewall) per peer. */
function mergeOpenwrt(node, tunnels) {
  const lines = [
    "[ -x /etc/init.d/swanctl ] || echo TMLAB-MISSING strongSwan is not installed, see the OpenWrt preparation in lab/gns3/README.md",
    "uci set system.@system[0].hostname='TM-OPENWRT'",
    "uci commit system",
    "uci set network.wan.proto='static'",
    `uci set network.wan.ipaddr='${node.wan_ip}'`,
    `uci set network.wan.netmask='${mask(node.wan_ip, node.prefix)}'`,
    `uci set network.lan.ipaddr='${node.lan_ip}'`,
    `uci set network.lan.netmask='${maskOf(node.lan)}'`,
    "uci commit network",
    "/etc/init.d/network restart",
    "sleep 8",
    ...extraLans(node).map((l) => `ip addr add ${l.ip}/${l.net.split("/")[1]} dev $(ifstatus lan | jsonfilter -e '@.l3_device')`),
    ...node.routes.map((r) => `ip route replace ${r.cidr} via ${r.via}`),
  ];
  tunnels.forEach((t) => {
    t.text.replace(/<PSK>/g, t.psk).split("\n").map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#") && !/^(\/etc\/init\.d\/|\[ -x \/etc\/init\.d\/ipsec|killall )/.test(l))
      .forEach((l) => lines.push(l));
  });
  lines.push(
    "/etc/init.d/firewall restart",
    "[ -x /etc/init.d/ipsec ] && { /etc/init.d/ipsec stop; /etc/init.d/ipsec disable; }",
    "killall -q -9 charon swanctl",
    "/etc/init.d/swanctl enable",
    "/etc/init.d/swanctl restart",
  );
  return { shell: lines };
}

function mergeStrongswan(node, tunnels) {
  const files = {};
  tunnels.forEach((t) => {
    // the tool's first line is "# /etc/swanctl/conf.d/<name>.conf, site A"
    const name = (t.text.match(/^# \/etc\/swanctl\/conf\.d\/([\w.-]+\.conf)\b/m) || [, `${t.peer.toLowerCase()}.conf`])[1];
    if (!/^[\w.-]+\.conf$/.test(name)) throw new Error(`strongSwan file name "${name}" for ${t.peer} does not end in .conf`);
    files[`/etc/swanctl/conf.d/${name}`] = t.text.replace(/<PSK>/g, t.psk) + "\n";
  });
  const shell = [
    `ip addr flush dev ${node.wan_if}`,
    `ip addr add ${node.wan_ip}/${node.prefix} dev ${node.wan_if}`,
    `ip link set ${node.wan_if} up`,
    // the LAN address sits on lo: works in any container, no dummy module needed
    `ip link set lo up`,
    ...node.lans.map((l) => `ip addr add ${l.ip}/32 dev lo`),
    ...node.routes.map((r) => `ip route replace ${r.cidr} via ${r.via} src ${node.lan_ip}`),
  ];
  return { files, shell };
}

/* ---------- helpers ---------- */

function maskOf(cidr) { return TM.maskStr(TM.parseCidr(cidr)); }
function mask(ip, prefix) { return maskOf(`${ip}/${prefix}`); }
function extraLans(node) { return node.lans.slice(1); }
function clean(lines) { return lines.filter((l) => l !== undefined && l.trim() !== ""); }

/* ---------- main ---------- */

function main() {
  const { cfg, cfgPath, profile, out, lans } = args();
  const prefix = Number(cfg.wan.net.split("/")[1]);
  const ids = Object.keys(KINDS).filter((id) => cfg.nodes[id] && cfg.nodes[id].enabled !== false);
  if (ids.length < 2) throw new Error("Enable at least two nodes in the lab config.");
  ids.forEach((id) => { cfg.nodes[id].lans = lansOf(cfg.nodes[id], lans); });

  const nodes = {};
  ids.forEach((id) => {
    const n = Object.assign({ id, kind: id, prefix }, cfg.nodes[id]);
    n.routes = ids.filter((o) => o !== id).flatMap((o) => cfg.nodes[o].lans.map(({ net }) =>
      ({ cidr: net, net: TM.netStr(TM.parseCidr(net)), mask: maskOf(net), via: cfg.nodes[o].wan_ip })));
    n.tunnels = [];
    nodes[id] = n;
  });

  const pairs = [];
  for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
    const a = ids[i], b = ids[j];
    const prof = pickProfile(cfg, a, b, profile);
    if (!prof) { pairs.push({ a, b, skipped: "no common profile without crypto errors" }); continue; }
    const S = stateFor(cfg, a, b, prof);
    const R = TM.analyze(S);
    const psk = crypto.randomBytes(16).toString("hex");
    SIDES.forEach((k) => {
      const me = k === "A" ? a : b, peer = k === "A" ? b : a;
      const blocks = toolConfig(S, k);
      nodes[me].tunnels.push({ peer: KINDS[peer].name, peerId: peer, psk, blocks, text: blocks[0].text });
    });
    pairs.push({
      a, b,
      profile: prof,
      label: profileLabel(prof),
      expect: expectFor(prof),
      verdict: {
        errors: R.issues.filter(([sev]) => sev === "err").map(([, t]) => t),
        cryptoErrors: R.issues.filter(([sev, , cat]) => sev === "err" && cat === "crypto").map(([, t]) => t),
        verify: R.issues.filter(([, , cat]) => cat === "verify").map(([, t]) => t),
      },
      // one ping per subnet pair and direction; each pair is its own SA
      pings: {
        a: cfg.nodes[a].lans.flatMap((la) => cfg.nodes[b].lans.map((lb) => ({ src: la.ping, dst: lb.ping }))),
        b: cfg.nodes[b].lans.flatMap((lb) => cfg.nodes[a].lans.map((la) => ({ src: lb.ping, dst: la.ping }))),
      },
      subnetPairs: cfg.nodes[a].lans.length * cfg.nodes[b].lans.length,
      peers: { a: cfg.nodes[a].wan_ip, b: cfg.nodes[b].wan_ip },
    });
  }

  const merge = { iosxe: mergeIosxe, asa: mergeAsa, opnsense: mergeOpnsense, pfsense: mergePfsense, strongswan: mergeStrongswan, mikrotik: mergeMikrotik, vsrx: mergeVsrx, vyos: mergeVyos, openwrt: mergeOpenwrt, panos: mergePanos };
  const planNodes = {};
  ids.forEach((id) => {
    const n = nodes[id];
    const merged = merge[id](n, n.tunnels);
    const { tunnels, routes, ...rest } = n;
    planNodes[id] = Object.assign(rest, { routes }, merged);
  });

  const plan = {
    generated: new Date().toISOString(),
    config: path.relative(process.cwd(), cfgPath),
    profile,
    server: cfg.server,
    project: cfg.project || "tunnelmatch-lab",
    nodes: planNodes,
    pairs,
  };

  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, "plan.json"), JSON.stringify(plan, null, 2));
  ids.forEach((id) => {
    const n = planNodes[id];
    let text;
    if (n.lines) text = n.lines.join("\n");
    else if (n.files) text = Object.entries(n.files).map(([f, c]) => `### ${f}\n${c}`).join("\n") + "\n### shell\n" + n.shell.join("\n");
    else if (!n.data) text = n.shell.join("\n");
    else text = JSON.stringify(n.data, null, 2) + "\n### shell\n" + n.shell.join("\n");
    fs.writeFileSync(path.join(out, `${id}.txt`), text + "\n");
  });

  console.log(`Plan: ${ids.length} nodes, ${pairs.length} tunnels, profile "${profile}"${lans > 1 ? `, ${lans} networks per node` : ""} → ${path.relative(process.cwd(), out)}/plan.json`);
  pairs.forEach((p) => console.log(`  ${KINDS[p.a].name.padEnd(10)} ↔ ${KINDS[p.b].name.padEnd(10)} ${p.skipped ? "skipped: " + p.skipped : p.label}${p.verdict && p.verdict.cryptoErrors.length ? "  (tool: crypto errors)" : ""}`));
}

if (require.main === module) {
  try { main(); } catch (e) { console.error(e.message); process.exit(1); }
}

module.exports = { parseOpnsense, parsePfsense, routerosCommands };
