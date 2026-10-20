#!/usr/bin/env node
/*
 * IPsec Tunnelmatch GNS3 lab: builds the test plan.
 *
 * For every pair of enabled nodes (full mesh) it picks a profile, runs the tool's own
 * checks and generators for both sides, and merges each node's tunnels into one
 * config. run.py then pushes the configs over the GNS3 consoles and verifies them.
 *
 *   node lab/gns3/generate.js [--config lab/gns3/lab.json] [--profile strongest|recommended|minimum]
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
  return { cfg, cfgPath, profile: get("--profile", cfg.profile || "strongest"), out: get("--out", path.join(HERE, "out")) };
}

/* A tool state for one tunnel between two lab nodes. */
function stateFor(cfg, a, b, crypto_) {
  const side = (id) => {
    const n = cfg.nodes[id];
    const v = TM.vendor(KINDS[id].vendor);
    return Object.assign({}, v.defaults, {
      name: KINDS[id].name,
      vendor: KINDS[id].vendor,
      ip: n.wan_ip,
      nets: n.lan,
      mode: "policy",
    }, id === "asa" ? { iface: "outside" } : {}, id === "iosxe" ? { iface: n.wan_if } : {});
  };
  const s = JSON.parse(JSON.stringify(Object.assign({}, BASE, { tunnelName: `${KINDS[a].name}-${KINDS[b].name}` }, crypto_ || {})));
  s.A = side(a);
  s.B = side(b);
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
    `interface Loopback1`, ` ip address ${node.lan_ip} ${maskOf(node.lan)}`, `!`,
    ...node.routes.map((r) => `ip route ${r.net} ${r.mask} ${r.via}`),
    ...body.join("\n!\n").split("\n"),
    `crypto ikev2 policy POL-TMLAB`,
    ...proposals.map((p) => ` proposal ${p}`),
    `!`,
  ];
  return { lines: clean(lines) };
}

function mergeAsa(node, tunnels) {
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
    shell: node.routes.map((r) => `route add -net ${r.cidr} ${r.via}`),
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
    shell: node.routes.map((r) => `route add -net ${r.cidr} ${r.via}`),
  };
}

function mergeStrongswan(node, tunnels) {
  const files = {};
  tunnels.forEach((t) => {
    const name = (t.text.match(/^# \/etc\/swanctl\/conf\.d\/(\S+)/m) || [, `${t.peer.toLowerCase()}.conf`])[1];
    files[`/etc/swanctl/conf.d/${name}`] = t.text.replace(/<PSK>/g, t.psk) + "\n";
  });
  const shell = [
    `ip addr flush dev ${node.wan_if}`,
    `ip addr add ${node.wan_ip}/${node.prefix} dev ${node.wan_if}`,
    `ip link set ${node.wan_if} up`,
    // the LAN address sits on lo: works in any container, no dummy module needed
    `ip link set lo up; ip addr add ${node.lan_ip}/32 dev lo`,
    ...node.routes.map((r) => `ip route replace ${r.cidr} via ${r.via} src ${node.lan_ip}`),
  ];
  return { files, shell };
}

/* ---------- helpers ---------- */

function maskOf(cidr) { return TM.maskStr(TM.parseCidr(cidr)); }
function mask(ip, prefix) { return maskOf(`${ip}/${prefix}`); }
function clean(lines) { return lines.filter((l) => l !== undefined && l.trim() !== ""); }

/* ---------- main ---------- */

function main() {
  const { cfg, cfgPath, profile, out } = args();
  const prefix = Number(cfg.wan.net.split("/")[1]);
  const ids = Object.keys(KINDS).filter((id) => cfg.nodes[id] && cfg.nodes[id].enabled !== false);
  if (ids.length < 2) throw new Error("Enable at least two nodes in the lab config.");

  const nodes = {};
  ids.forEach((id) => {
    const n = Object.assign({ id, kind: id, prefix }, cfg.nodes[id]);
    n.routes = ids.filter((o) => o !== id).map((o) => {
      const net = cfg.nodes[o].lan;
      return { cidr: net, net: TM.netStr(TM.parseCidr(net)), mask: maskOf(net), via: cfg.nodes[o].wan_ip };
    });
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
      ping: { a: { src: cfg.nodes[a].lan_ip, dst: cfg.nodes[b].lan_ip }, b: { src: cfg.nodes[b].lan_ip, dst: cfg.nodes[a].lan_ip } },
      peers: { a: cfg.nodes[a].wan_ip, b: cfg.nodes[b].wan_ip },
    });
  }

  const merge = { iosxe: mergeIosxe, asa: mergeAsa, opnsense: mergeOpnsense, pfsense: mergePfsense, strongswan: mergeStrongswan };
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
    else text = JSON.stringify(n.data, null, 2) + "\n### shell\n" + n.shell.join("\n");
    fs.writeFileSync(path.join(out, `${id}.txt`), text + "\n");
  });

  console.log(`Plan: ${ids.length} nodes, ${pairs.length} tunnels, profile "${profile}" → ${path.relative(process.cwd(), out)}/plan.json`);
  pairs.forEach((p) => console.log(`  ${KINDS[p.a].name.padEnd(10)} ↔ ${KINDS[p.b].name.padEnd(10)} ${p.skipped ? "skipped: " + p.skipped : p.label}${p.verdict && p.verdict.cryptoErrors.length ? "  (tool: crypto errors)" : ""}`));
}

if (require.main === module) {
  try { main(); } catch (e) { console.error(e.message); process.exit(1); }
}

module.exports = { parseOpnsense, parsePfsense };
