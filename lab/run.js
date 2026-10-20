#!/usr/bin/env node
/*
 * IPsec Tunnelmatch lab: verifies generated configs with real IKEv2 negotiations.
 *
 * For each scenario it creates two Linux network namespaces ("site A" and
 * "site B") joined by a veth link, starts one strongSwan daemon in each,
 * loads the configs the tool generates, and then checks:
 *   1. the IKE SA and every child SA come up (or fail, for negative tests)
 *   2. the negotiated algorithms match what the tool generated
 *   3. traffic flows between every local/remote subnet pair
 *   4. a child SA rekey works and uses the PFS group
 *   5. the tool's own checks agree with the outcome
 *
 * Needs root, iproute2 and strongSwan (swanctl + charon-systemd). ESP runs in
 * userspace (kernel-libipsec) by default so results do not depend on the host
 * kernel's crypto modules; pass --kernel to use the kernel's XFRM instead.
 *
 * Usage: sudo node lab/run.js [--kernel] [--only <text>] [--keep] [--quiet]
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync, spawn } = require("child_process");
const { loadTool, ROOT } = require("./tm.js");
const { FIXED, profile } = require("./scenarios.js");

/* ---------- options ---------- */

const argv = process.argv.slice(2);
const OPT = {
  kernel: argv.includes("--kernel"),
  keep: argv.includes("--keep"),
  quiet: argv.includes("--quiet"),
  only: argv.includes("--only") ? argv[argv.indexOf("--only") + 1].toLowerCase() : null,
};

const TM = loadTool();
const log = (...a) => { if (!OPT.quiet) console.log(...a); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- prerequisites ---------- */

function which(cmd, extra = []) {
  for (const dir of (process.env.PATH || "").split(":").concat(extra)) {
    const p = path.join(dir, cmd);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function preflight() {
  const problems = [];
  if (process.getuid && process.getuid() !== 0) problems.push("run as root (network namespaces need it): sudo node lab/run.js");
  const ip = which("ip", ["/usr/sbin", "/sbin"]);
  const swanctl = which("swanctl", ["/usr/sbin"]);
  const charon = process.env.CHARON || which("charon-systemd", ["/usr/sbin", "/usr/lib/ipsec", "/usr/libexec/ipsec"]);
  if (!ip) problems.push("iproute2 (ip) is missing");
  if (!swanctl) problems.push("swanctl is missing (apt install strongswan-swanctl)");
  if (!charon) problems.push("charon-systemd is missing (apt install charon-systemd), or set CHARON=/path/to/charon");
  const libipsec = ["/usr/lib/ipsec/plugins", "/usr/lib/x86_64-linux-gnu/ipsec/plugins", "/usr/lib/aarch64-linux-gnu/ipsec/plugins"]
    .some((d) => fs.existsSync(path.join(d, "libstrongswan-kernel-libipsec.so")));
  if (!OPT.kernel && !libipsec) problems.push("kernel-libipsec plugin is missing (apt install libcharon-extra-plugins), or use --kernel");
  if (!OPT.kernel && !fs.existsSync("/dev/net/tun")) problems.push("/dev/net/tun is missing (needed for userspace ESP), or use --kernel");
  if (problems.length) {
    console.error("Lab prerequisites not met:\n  - " + problems.join("\n  - "));
    process.exit(2);
  }
  return { ip, swanctl, charon, stdbuf: which("stdbuf", ["/usr/bin"]) };
}

/* ---------- strongSwan names for the tool's neutral ids ---------- */

const SW = {
  enc: { aes128: ["AES_CBC", 128], aes192: ["AES_CBC", 192], aes256: ["AES_CBC", 256], aes128gcm: ["AES_GCM_16", 128], aes256gcm: ["AES_GCM_16", 256] },
  token: { aes128: "aes128", aes192: "aes192", aes256: "aes256", aes128gcm16: "aes128gcm", aes256gcm16: "aes256gcm" },
  integ: { sha1: "HMAC_SHA1_96", sha256: "HMAC_SHA2_256_128", sha384: "HMAC_SHA2_384_192", sha512: "HMAC_SHA2_512_256", md5: "HMAC_MD5_96" },
  prf: { sha1: "PRF_HMAC_SHA1", sha256: "PRF_HMAC_SHA2_256", sha384: "PRF_HMAC_SHA2_384", sha512: "PRF_HMAC_SHA2_512", md5: "PRF_HMAC_MD5" },
  dh: { modp1024: "MODP_1024", modp1536: "MODP_1536", modp2048: "MODP_2048", modp3072: "MODP_3072", ecp256: "ECP_256", ecp384: "ECP_384", ecp521: "ECP_521", modp2048s256: "MODP_2048_256" },
};

/* Parse a strongSwan proposal string into what list-sas should report. */
function parseProposal(str, ike) {
  const out = {};
  for (const t of str.trim().split("-")) {
    if (SW.token[t]) {
      const e = SW.enc[SW.token[t]];
      out.encr = `${e[0]}-${e[1]}`;
    } else if (t.startsWith("prf") && SW.prf[t.slice(3)]) out.prf = SW.prf[t.slice(3)];
    else if (SW.integ[t]) {
      out.integ = SW.integ[t];
      if (ike && !out.prf) out.prf = SW.prf[t]; // strongSwan derives the PRF from the integrity algorithm
    } else if (SW.dh[t]) out.dh = SW.dh[t];
  }
  return out;
}

/*
 * Parse `swanctl --list-sas --raw`: one "list-sa event {...}" line per IKE SA,
 * with the child SAs nested under "child-sas {...}".
 */
function parseSas(raw) {
  const field = (s, k) => (s.match(new RegExp(`(?:^|[ {])${k}=(\\S+?)(?=[ }]|$)`)) || [])[1];
  const encr = (s) => field(s, "encr-alg") && `${field(s, "encr-alg")}-${field(s, "encr-keysize")}`;
  return raw.split("\n").filter((l) => l.startsWith("list-sa event {")).map((line) => {
    const body = line.slice("list-sa event {".length);
    const at = body.indexOf("child-sas {");
    const head = at >= 0 ? body.slice(0, at) : body;
    const kids = at >= 0 ? body.slice(at) : "";
    const children = [...kids.matchAll(/\{name=([^ }]+)([^}]*)\}/g)].map(([, name, rest]) => ({
      name,
      id: field(rest, "uniqueid"),
      state: field(rest, "state"),
      encr: encr(rest),
      integ: field(rest, "integ-alg"),
      dh: field(rest, "dh-group"),
    }));
    return {
      name: body.split(" ")[0],
      state: field(head, "state"),
      encr: encr(head),
      integ: field(head, "integ-alg"),
      prf: field(head, "prf-alg"),
      dh: field(head, "dh-group"),
      children,
    };
  });
}

/* ---------- one lab run ---------- */

const SIDES = ["A", "B"];
const tag = String(process.pid % 10000);
const NS = { A: `tml${tag}a`, B: `tml${tag}b` };

class Lab {
  constructor(bins) {
    this.bins = bins;
    this.dir = fs.mkdtempSync(path.join(os.tmpdir(), "tmlab-"));
    this.procs = [];
  }

  /* Run a command, optionally inside one of the namespaces. */
  sh(args, { ns, allowFail = false } = {}) {
    const [cmd, ...rest] = ns ? [this.bins.ip, "netns", "exec", ns, ...args] : args;
    try {
      return execFileSync(cmd, rest, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      if (allowFail) return (e.stdout || "") + (e.stderr || "");
      throw new Error(`${[cmd, ...rest].join(" ")}\n${e.stderr || e.message}`);
    }
  }
  ip(...args) { return this.sh([this.bins.ip, ...args]); }
  uri(k) { return `unix://${path.join(this.dir, k, "charon.vici")}`; }
  swanctl(k, ...args) { return this.sh([this.bins.swanctl, ...args, "--uri", this.uri(k)], { ns: NS[k], allowFail: true }); }

  network(state) {
    SIDES.forEach((k) => this.sh([this.bins.ip, "netns", "del", NS[k]], { allowFail: true })); // leftovers from an aborted run
    this.ip("link", "add", `${NS.A}w`, "type", "veth", "peer", "name", `${NS.B}w`);
    SIDES.forEach((k) => {
      this.ip("netns", "add", NS[k]);
      this.ip("link", "set", `${NS[k]}w`, "netns", NS[k]);
    });
    SIDES.forEach((k) => {
      const o = k === "A" ? "B" : "A";
      const n = NS[k];
      this.ip("-n", n, "link", "set", "lo", "up");
      this.ip("-n", n, "addr", "add", `${state[k].ip}/32`, "dev", `${n}w`);
      this.ip("-n", n, "link", "set", `${n}w`, "up");
      this.ip("-n", n, "route", "add", `${state[o].ip}/32`, "dev", `${n}w`);
    });
    // One host address per local network, on loopback, to send test traffic from.
    this.hosts = {};
    SIDES.forEach((k) => {
      this.hosts[k] = state[k].nets.split(/\s+/).filter(Boolean).map((cidr) => {
        const c = TM.parseCidr(cidr);
        const host = TM.i2s(c.net + 1);
        this.ip("-n", NS[k], "addr", "add", `${host}/32`, "dev", "lo");
        return { cidr: c.text, host };
      });
    });
  }

  async start(configs) {
    for (const k of SIDES) {
      const d = path.join(this.dir, k);
      fs.mkdirSync(d);
      fs.writeFileSync(path.join(d, "swanctl.conf"), configs[k]);
      fs.writeFileSync(path.join(d, "strongswan.conf"), `charon-systemd {
  load_modular = yes
  journal { default = -1 }
  retransmit_tries = 2
  retransmit_timeout = 1.0
  retransmit_base = 1.5
  plugins {
    include /etc/strongswan.d/charon/*.conf
    ${OPT.kernel ? "" : "kernel-libipsec { load = yes }"}
    vici { socket = ${this.uri(k)} }
  }
}
`);
      const out = fs.openSync(path.join(d, "charon.out"), "w");
      const p = spawn(this.bins.ip, ["netns", "exec", NS[k], "env", `STRONGSWAN_CONF=${path.join(d, "strongswan.conf")}`, this.bins.charon],
        { detached: true, stdio: ["ignore", out, out] });
      this.procs.push(p);
    }
    for (const k of SIDES) {
      const sock = path.join(this.dir, k, "charon.vici");
      for (let i = 0; i < 50 && !fs.existsSync(sock); i++) await sleep(100);
      if (!fs.existsSync(sock)) throw new Error(`strongSwan did not start on side ${k}`);
      // Capture the negotiation log for the report.
      const logFile = fs.openSync(path.join(this.dir, k, "ike.log"), "w");
      // stdbuf keeps swanctl's output line-buffered so nothing is lost when it is stopped.
      const logCmd = this.bins.stdbuf ? [this.bins.stdbuf, "-oL", this.bins.swanctl] : [this.bins.swanctl];
      this.procs.push(spawn(this.bins.ip, ["netns", "exec", NS[k], ...logCmd, "--log", "--uri", this.uri(k)],
        { detached: true, stdio: ["ignore", logFile, logFile] }));
    }
    await sleep(300);
    this.loaded = {};
    // Responder first, so side A's first attempt finds side B ready.
    for (const k of ["B", "A"]) this.loaded[k] = this.swanctl(k, "--load-all", "--file", path.join(this.dir, k, "swanctl.conf"));
  }

  sas(k) { return parseSas(this.swanctl(k, "--list-sas", "--raw")); }

  async waitFor(children, seconds) {
    const until = Date.now() + seconds * 1000;
    while (Date.now() < until) {
      const ike = this.sas("A").find((s) => s.state === "ESTABLISHED");
      if (ike && children.every((n) => ike.children.some((c) => c.name === n && c.state === "INSTALLED"))) return ike;
      await sleep(250);
    }
    return null;
  }

  ping(src, dst) {
    const out = this.sh(["ping", "-c", "2", "-W", "2", "-I", src, dst], { ns: NS.A, allowFail: true });
    return /\b[12] received\b/.test(out);
  }

  logLines(k, re) {
    try { return fs.readFileSync(path.join(this.dir, k, "ike.log"), "utf8").split("\n").filter((l) => re.test(l)); } catch (e) { return []; }
  }

  stop() {
    for (const p of this.procs) { try { process.kill(-p.pid, "SIGTERM"); } catch (e) { /* already gone */ } }
    if (OPT.keep) return;
    SIDES.forEach((k) => this.sh([this.bins.ip, "netns", "del", NS[k]], { allowFail: true }));
    fs.rmSync(this.dir, { recursive: true, force: true });
  }
}

/* ---------- scenario execution ---------- */

function generate(state, emulate) {
  const s = JSON.parse(JSON.stringify(state));
  SIDES.forEach((k) => { s[k].vendor = "strongswan"; s[k].mode = "policy"; });
  const R = TM.analyze(s);
  const psk = crypto.randomBytes(24).toString("hex");
  const out = {};
  for (const k of SIDES) {
    let conf = TM.vendor("strongswan").generate(TM.contextFor(s, k, R)).replace(/<PSK>/g, psk);
    const e = (emulate || {})[k] || {};
    if (e.proposals) conf = conf.replace(/^(\s*)proposals = .*$/m, `$1proposals = ${e.proposals}`);
    if (e.esp) conf = conf.replace(/^(\s*)esp_proposals = .*$/gm, `$1esp_proposals = ${e.esp}`);
    out[k] = conf;
  }
  const children = [...out.A.matchAll(/^\s{6}(\S+) \{$/gm)].map((m) => m[1]);
  return { configs: out, children };
}

/* The tool's own verdict for the platforms a scenario stands for. */
function toolVerdict(state, vendors) {
  const s = JSON.parse(JSON.stringify(state));
  SIDES.forEach((k) => {
    s[k].vendor = vendors[k];
    s[k].mode = TM.vendor(vendors[k]).modes[0];
    s[k].types = "./types.bicep";
  });
  const errs = TM.analyze(s).issues.filter(([sev, , cat]) => sev === "err" && cat === "crypto").map(([, t]) => t);
  return { cryptoErrors: errs };
}

const fmt = (o) => [o.encr, o.integ, o.prf, o.dh].filter(Boolean).join(" / ");

async function runScenario(bins, sc) {
  const res = { name: sc.name, expect: sc.expect, checks: [], ok: true };
  const check = (ok, text) => { res.checks.push({ ok, text }); if (!ok) res.ok = false; };

  const { configs, children } = generate(sc.state, sc.emulate);
  const wantIke = parseProposal(configs.A.match(/^\s*proposals = (.*)$/m)[1], true);
  const wantEsp = parseProposal(configs.A.match(/^\s*esp_proposals = (.*)$/m)[1], false);
  res.wantIke = fmt(wantIke);
  res.wantEsp = fmt(wantEsp);

  if (sc.vendors) {
    const v = toolVerdict(sc.state, sc.vendors);
    const toolSaysFail = v.cryptoErrors.length > 0;
    check(toolSaysFail === (sc.expect === "fail"),
      `Tool verdict for ${TM.vendor(sc.vendors.A).short} ↔ ${TM.vendor(sc.vendors.B).short}: ` +
      (toolSaysFail ? `error (${v.cryptoErrors[0]})` : "no crypto errors"));
  }
  (sc.covers || []).forEach((pair) => {
    const v = toolVerdict(sc.state, pair);
    check(v.cryptoErrors.length === 0, `Tool reports no crypto errors for ${TM.vendor(pair.A).short} ↔ ${TM.vendor(pair.B).short}`);
  });

  const lab = new Lab(bins);
  try {
    lab.network(sc.state);
    await lab.start(configs);
    SIDES.forEach((k) => check(/successfully loaded 1 connections/.test(lab.loaded[k]), `Side ${k} config loads in swanctl`));

    const ike = await lab.waitFor(children, sc.expect === "pass" ? 20 : 8);
    if (sc.expect === "fail") {
      check(!ike, "Tunnel does not come up");
      await sleep(300);
      const startupRace = /no IKE config found/; // a side that has not loaded its config yet
      const reason = lab.logLines("B", /no acceptable proposal|no matching proposal|NO_PROPOSAL_CHOSEN/)
        .concat(lab.logLines("A", /NO_PROPOSAL_CHOSEN|no acceptable proposal|failed to establish/))
        .find((l) => !startupRace.test(l));
      res.detail = reason ? reason.replace(/^\s*\d+\[\w+\] /, "").trim() : "";
      if (res.detail) check(true, `Rejected: ${res.detail}`);
      return res;
    }

    check(!!ike, `IKE SA and all ${children.length} child SA(s) established`);
    if (!ike) {
      res.detail = lab.logLines("A", /NO_PROPOSAL|failed|error|unable/i).slice(0, 3).join(" | ");
      return res;
    }
    res.gotIke = fmt(ike);
    check(res.gotIke === res.wantIke, `IKE negotiated ${res.gotIke} (expected ${res.wantIke})`);
    const child = ike.children.find((c) => c.state === "INSTALLED");
    res.gotEsp = fmt({ encr: child.encr, integ: child.integ });
    const wantEspNoDh = fmt({ encr: wantEsp.encr, integ: wantEsp.integ });
    check(res.gotEsp === wantEspNoDh, `ESP negotiated ${res.gotEsp} (expected ${wantEspNoDh})`);

    // Traffic between every local subnet on A and every local subnet on B.
    for (const a of lab.hosts.A) for (const b of lab.hosts.B)
      check(lab.ping(a.host, b.host), `Traffic ${a.cidr} → ${b.cidr} passes through the tunnel`);

    // Rekey every child; with PFS the new SA must use the PFS group.
    const before = new Set(lab.sas("A").flatMap((s) => s.children.map((c) => c.id)));
    for (const name of children) lab.swanctl("A", "--rekey", "--child", name);
    const until = Date.now() + 10000;
    let rekeyed = [];
    while (Date.now() < until) {
      rekeyed = lab.sas("A").flatMap((s) => s.children).filter((c) => c.state === "INSTALLED" && !before.has(c.id));
      if (children.every((n) => rekeyed.some((c) => c.name === n))) break;
      await sleep(250);
    }
    const allRekeyed = children.every((n) => rekeyed.some((c) => c.name === n));
    check(allRekeyed, "Child SA rekey succeeds");
    if (allRekeyed && wantEsp.dh) {
      const groups = [...new Set(rekeyed.map((c) => c.dh))];
      check(groups.length === 1 && groups[0] === wantEsp.dh, `PFS after rekey uses ${groups.join(", ") || "no group"} (expected ${wantEsp.dh})`);
    }
    if (allRekeyed) {
      const a = lab.hosts.A[0], b = lab.hosts.B[0];
      check(lab.ping(a.host, b.host), "Traffic still passes after rekey");
    }
    return res;
  } catch (e) {
    check(false, "Lab error: " + e.message.split("\n")[0]);
    return res;
  } finally {
    lab.stop();
  }
}

/* Strongest common profile for every platform pair, grouped by identical profile. */
function pairScenarios() {
  const ids = TM.vendorIds();
  const groups = new Map();
  for (let i = 0; i < ids.length; i++) for (let j = i; j < ids.length; j++) {
    const s = profile({ p1enc: "aes256", p1int: "sha256", dh: 14, p2enc: "aes256", p2int: "sha256", pfs: 14 });
    s.A.vendor = ids[i]; s.B.vendor = ids[j];
    s.A.mode = TM.vendor(ids[i]).modes[0]; s.B.mode = TM.vendor(ids[j]).modes[0];
    const best = TM.baseline.strongestProfile(s);
    if (!best) continue;
    const key = JSON.stringify(best);
    if (!groups.has(key)) groups.set(key, { best, pairs: [] });
    groups.get(key).pairs.push({ A: ids[i], B: ids[j] });
  }
  return [...groups.values()].map(({ best, pairs }) => {
    const label = `${TM.encLabel(best.p1enc)} / ${TM.intLabel(best.p1int)} / group ${best.dh} · ESP ${TM.encLabel(best.p2enc)}` +
      (TM.isGcm(best.p2enc) ? "" : " / " + TM.intLabel(best.p2int)) + ` · PFS ${best.pfs}`;
    return {
      name: `Strongest common profile: ${label} (${pairs.length} platform pairs)`,
      state: profile(best),
      covers: pairs,
      expect: "pass",
    };
  });
}

/* ---------- report ---------- */

function markdown(results, meta) {
  const rows = results.map((r) => r.expect === "fail"
    ? `| ${r.ok ? "✅" : "❌"} | ${r.name} | must fail | ${r.ok ? "Rejected as expected" : "Came up unexpectedly"}${r.detail ? `: ${r.detail}` : ""} | — |`
    : `| ${r.ok ? "✅" : "❌"} | ${r.name} | must work | ${r.gotIke || "not established"} | ${r.gotEsp || "—"} |`);
  const failed = results.filter((r) => !r.ok);
  return [
    `## IPsec Tunnelmatch lab: ${failed.length ? `${failed.length} of ${results.length} scenarios failed` : `all ${results.length} scenarios passed`}`,
    "",
    `strongSwan ${meta.version} · ESP in ${OPT.kernel ? "kernel (XFRM)" : "userspace (kernel-libipsec)"} · ${meta.date}`,
    "",
    "| | Scenario | Expected | Negotiated IKE | Negotiated ESP |",
    "|---|---|---|---|---|",
    ...rows,
    "",
    ...results.flatMap((r) => [
      `### ${r.ok ? "✅" : "❌"} ${r.name}`,
      ...r.checks.map((c) => `- ${c.ok ? "✅" : "❌"} ${c.text}`),
      "",
    ]),
  ].join("\n");
}

async function main() {
  const bins = preflight();
  // swanctl prints its own version even when no daemon answers.
  let banner = "";
  try { banner = execFileSync(bins.swanctl, ["--help"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
  catch (e) { banner = (e.stdout || "") + (e.stderr || ""); }
  const version = (banner.match(/strongSwan (\d+\.\d+\.\d+)/) || [, "?"])[1];
  let scenarios = FIXED.concat(pairScenarios());
  if (OPT.only) scenarios = scenarios.filter((s) => s.name.toLowerCase().includes(OPT.only));
  if (!scenarios.length) { console.error(`No scenario name contains "${OPT.only}".`); process.exit(2); }

  log(`IPsec Tunnelmatch lab · strongSwan ${version} · ESP in ${OPT.kernel ? "kernel" : "userspace"} · ${scenarios.length} scenarios\n`);
  const results = [];
  for (const sc of scenarios) {
    const r = await runScenario(bins, sc);
    results.push(r);
    log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
    r.checks.forEach((c) => log(`      ${c.ok ? "ok  " : "FAIL"} ${c.text}`));
    if (r.detail) log(`      log: ${r.detail}`);
  }

  const md = markdown(results, { version, date: new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC" });
  const outDir = path.join(ROOT, "lab", "results");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "latest.md"), md + "\n");
  fs.writeFileSync(path.join(outDir, "latest.json"), JSON.stringify(results, null, 2) + "\n");
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + "\n");

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${failed ? `${failed} of ${results.length} scenarios FAILED` : `All ${results.length} scenarios passed`} · report: lab/results/latest.md`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(2); });
