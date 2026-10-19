/*
 * IPsec Tunnelmatch – checks and traffic-selector reconciliation
 *
 * TM.analyze(S) returns:
 *   issues     [severity, text] pairs (severity: err | warn | ok | info)
 *   A, B       parsed networks per side { nets, bad }
 *   eff        effective VPN type per side { mode, narrowed, switched }
 *   pairs      every local-A × local-B subnet pair
 *   selectors  the pairs when narrow selectors apply, otherwise null (any/any)
 *
 * Generic rules live here; anything specific to one platform lives in that
 * vendor's file as checks() (per side) and notes() (once per platform).
 */
(function () {
  "use strict";
  const { isGcm, encLabel, intLabel, netStr, overlap, validIp, parseCidr, LEGACY } = TM;
  const SIDES = ["A", "B"];

  function parseSide(s) {
    const nets = [], bad = [];
    s.nets.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean).forEach((raw) => {
      const c = parseCidr(raw);
      c ? nets.push(c) : bad.push(raw);
    });
    return { nets, bad };
  }

  /* The VPN type a side actually runs: the chosen one if the platform allows it. */
  function modeOf(S, k) {
    const v = TM.vendor(S[k].vendor);
    return v.modes.includes(S[k].mode) ? S[k].mode : v.modes[0];
  }

  function analyze(S) {
    const issues = [];
    const add = (sev, text) => issues.push([sev, text]);
    const parsed = { A: parseSide(S.A), B: parseSide(S.B) };
    const { A, B } = parsed;

    /* --- endpoints --- */
    SIDES.forEach((k) => {
      const x = parsed[k];
      if (x.bad.length) add("err", `Side ${k}: invalid CIDR: ${x.bad.join(", ")}`);
      x.nets.forEach((c) => {
        if (c.ip !== c.net) add("warn", `Side ${k}: ${c.text} is not a network address (becomes ${netStr(c)}/${c.prefix}).`);
      });
      if (!x.nets.length) add("err", `Side ${k}: no local networks entered.`);
      if (!validIp(S[k].ip)) add("err", `Side ${k}: public IP is missing or invalid.`);
    });
    A.nets.forEach((a) => B.nets.forEach((b) => {
      if (overlap(a, b)) add("err", `Overlapping networks: ${a.text} (A) and ${b.text} (B). NAT is needed before this tunnel can work.`);
    }));
    if (S.A.ip && S.A.ip === S.B.ip) add("err", "Both sides have the same public IP.");

    /* --- algorithm support on both platforms --- */
    const supported = (field, value, label) => SIDES.forEach((k) => {
      const v = TM.vendor(S[k].vendor);
      const group = field.replace(/^p[12]/, ""); // verify lists are keyed dh / pfs
      if (!v.supports[field].includes(value)) add("err", `${label} is not supported by ${v.label} (side ${k}).`);
      else if (v.verify[group] && v.verify[group].includes(value)) add("warn", `${label} on ${v.short} (side ${k}): ${v.verifyNote}`);
    });
    supported("p1enc", S.p1enc, "Phase 1 encryption " + encLabel(S.p1enc));
    supported("p1int", S.p1int, (isGcm(S.p1enc) ? "PRF " : "Phase 1 integrity ") + intLabel(S.p1int));
    supported("dh", S.dh, "DH group " + S.dh);
    supported("p2enc", S.p2enc, "Phase 2 encryption " + encLabel(S.p2enc));
    if (!isGcm(S.p2enc)) supported("p2int", S.p2int, "Phase 2 integrity " + intLabel(S.p2int));
    if (S.pfs) supported("pfs", S.pfs, "PFS group " + S.pfs);

    /* --- weak algorithms and basic sanity --- */
    if (LEGACY.enc.includes(S.p1enc) || LEGACY.enc.includes(S.p2enc))
      add("warn", "3DES is deprecated and is being removed in newer firmware (for example Meraki MX 27.1).");
    if (LEGACY.int.includes(S.p1int) || (!isGcm(S.p2enc) && LEGACY.int.includes(S.p2int)))
      add("warn", "SHA-1 and MD5 are weak. Choose SHA-256 or stronger.");
    if (LEGACY.dh.includes(S.dh) || LEGACY.dh.includes(S.pfs))
      add("warn", "DH groups 2 and 5 are weak. Group 14 or higher is recommended.");
    if (!(S.dpdInt > 0) || !(S.dpdRetry > 0))
      add("err", "DPD interval and retries must both be positive numbers.");

    /* --- platform-specific rules --- */
    SIDES.forEach((k) => {
      const v = TM.vendor(S[k].vendor);
      if (v.checks) v.checks({ S, k, A, B, add });
    });
    [...new Set([S.A.vendor, S.B.vendor])].forEach((id) => {
      const v = TM.vendor(id);
      if (v.notes) v.notes({ S, add });
    });

    /* --- route-based vs policy-based --- */
    const pairs = [];
    A.nets.forEach((a) => B.nets.forEach((b) => pairs.push([a, b])));
    const eff = {
      A: { mode: modeOf(S, "A"), narrowed: false, switched: false },
      B: { mode: modeOf(S, "B"), narrowed: false, switched: false },
    };

    /* The route-based side r must match the policy-based side p. */
    const reconcile = (r, p) => {
      const v = TM.vendor(S[r].vendor);
      if (v.narrow) {
        eff[r].narrowed = true;
        add("ok", `Side ${p} is policy-based and side ${r} is route-based. Side ${r} (${v.short}) gets narrow traffic selectors, one per subnet pair (${pairs.length}), instead of 0.0.0.0/0.` + (v.narrowNote ? " " + v.narrowNote : ""));
      } else {
        eff[r].mode = "policy";
        eff[r].switched = true;
        add("warn", `Side ${r} (${v.short}) cannot narrow selectors on a route-based interface, so its config is generated as policy-based to match side ${p}.`);
      }
    };
    if (eff.A.mode === "policy" && eff.B.mode === "route") reconcile("B", "A");
    else if (eff.B.mode === "policy" && eff.A.mode === "route") reconcile("A", "B");

    const anyAny = eff.A.mode === "route" && eff.B.mode === "route" && !eff.A.narrowed && !eff.B.narrowed;
    if (anyAny) {
      add("ok", "Both sides route-based: selectors 0.0.0.0/0 ↔ 0.0.0.0/0; routing decides what enters the tunnel.");
    } else if (pairs.length > 1 && SIDES.some((k) => TM.vendor(S[k].vendor).multiSaNote)) {
      add("info", `Policy-based with ${pairs.length} subnet pairs: each pair becomes its own phase 2 SA. Check that the peer allows several SAs toward the same peer.`);
    }

    return { issues, A, B, eff, pairs, selectors: anyAny ? null : pairs };
  }

  /* Everything a vendor's generate() needs for one side. */
  function contextFor(S, k, R) {
    const o = k === "A" ? "B" : "A";
    return {
      S, k,
      me: S[k],
      peer: S[o],
      local: R[k].nets,
      remote: R[o].nets,
      eff: R.eff[k],
      pairs: R.pairs.map((p) => (k === "A" ? p : [p[1], p[0]])),
      anyAny: !R.selectors,
      name: TM.slug(S[o].name).toUpperCase(),
    };
  }

  /* Name mapping: the neutral value next to each side's own spelling. */
  function nameRows(S) {
    const a = TM.vendor(S.A.vendor).names(S);
    const b = TM.vendor(S.B.vendor).names(S);
    const row = (label, neutral, key) => [label, neutral, a[key], b[key]];
    return [
      row("Phase 1 encryption", encLabel(S.p1enc), "p1enc"),
      row(isGcm(S.p1enc) ? "Phase 1 PRF" : "Phase 1 integrity", intLabel(S.p1int), "p1int"),
      row("DH group", TM.dhLabel(S.dh), "dh"),
      row("Phase 2 encryption", encLabel(S.p2enc), "p2enc"),
      row("Phase 2 integrity", isGcm(S.p2enc) ? "(GCM)" : intLabel(S.p2int), "p2int"),
      row("PFS", TM.dhLabel(S.pfs), "pfs"),
      row("DPD", `${S.dpdInt} s × ${S.dpdRetry}`, "dpd"),
    ];
  }

  TM.analyze = analyze;
  TM.contextFor = contextFor;
  TM.nameRows = nameRows;
})();
