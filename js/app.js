/*
 * IPsec Tunnelmatch – page logic
 *
 * Holds the form state, renders the endpoint panels, crypto selects, checks,
 * traffic selectors, output tabs and sources, and saves the PDF.
 * Vendor knowledge lives in js/vendors/*.js; rules in js/analyze.js.
 */
(function () {
  "use strict";
  const { ENC, INT, DH, PFS, isGcm, encLabel, esc, slug } = TM;
  // TM.baseline (js/baseline.js) grades the profile and holds the go-live checklist.
  const $ = (id) => document.getElementById(id);
  const SIDES = ["A", "B"];

  /* ---------- state ---------- */

  const STORAGE_KEY = "ipsec-tunnelmatch-v2";
  const DEFAULTS = {
    tunnelName: "SITE-A-SITE-B-01",
    author: "",
    p1enc: "aes256", p1int: "sha256", dh: 14, p1life: 28800,
    dpdInt: 10, dpdRetry: 3,
    p2enc: "aes256gcm", p2int: "aes256gcm", pfs: 14, p2life: 3600, p2kb: 102400000,
    checklist: {},
    A: { name: "Site A", vendor: "paloalto", ip: "203.0.113.10", nets: "10.10.0.0/16\n10.20.30.0/24",
         mode: "route", iface: "ethernet1/1", tun: "tunnel.10", rg: "", gw: "", loc: "", cmode: "Default", types: "./types.bicep" },
    B: { name: "Site B", vendor: "azure", ip: "198.51.100.20", nets: "10.50.0.0/16",
         mode: "route", iface: "", tun: "", rg: "rg-network-prod", gw: "vgw-hub-prod", loc: "swedencentral", cmode: "Default", types: "./types.bicep" },
  };

  function loadState() {
    let s = null;
    try { s = JSON.parse(localStorage.getItem(STORAGE_KEY)); } catch (e) { s = null; }
    if (!s || !s.A || !s.B || !TM.vendor(s.A.vendor) || !TM.vendor(s.B.vendor)) s = JSON.parse(JSON.stringify(DEFAULTS));
    // Drop fields from older versions: the key is never stored, and IKEv1 is gone.
    delete s.psk; delete s.pskInPdf; delete s.ikev;
    if (!s.checklist) s.checklist = {};
    // Older default names: replace them unless they were changed.
    if (["HQ-AZURE-PROD-01", "SIDE-A-SIDE-B-01"].includes(s.tunnelName)) s.tunnelName = DEFAULTS.tunnelName;
    if (["Head office", "Side A"].includes(s.A.name)) s.A.name = DEFAULTS.A.name;
    if (["Azure prod", "Side B"].includes(s.B.name)) s.B.name = DEFAULTS.B.name;
    SIDES.forEach((k) => {
      if (!s[k].types) s[k].types = "./types.bicep";
      if (!s[k].cmode) s[k].cmode = "Default";
    });
    return s;
  }

  const S = loadState();
  const save = () => { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(S)); } catch (e) { /* storage unavailable */ } };

  /* ---------- endpoint panels ---------- */

  const SIDE_FIELDS = ["name", "ip", "nets", "iface", "tun", "rg", "gw", "loc", "types", "cmode", "mode"];
  const SELECT_FIELDS = ["mode", "cmode"];

  function sidePanel(k) {
    const options = TM.vendorIds().map((id) => `<option value="${id}">${esc(TM.vendor(id).label)}</option>`).join("");
    return `
      <div class="panel-head"><h2 id="h${k}">Side ${k}</h2><span class="side-tag">${k}</span></div>
      <div class="grid2">
        <label class="full">Platform<select id="${k}vendor">${options}</select></label>
        <label>Site / organisation<input id="${k}name"></label>
        <label>Public IP<input id="${k}ip" class="mono" inputmode="decimal"></label>
        <label class="full">Local networks (one CIDR per line)<textarea id="${k}nets" rows="3" spellcheck="false"></textarea></label>
        <label>VPN type<select id="${k}mode"><option value="route">Route-based (VTI)</option><option value="policy">Policy-based</option></select></label>
        <label id="${k}ifaceL"><span id="${k}ifaceT">WAN interface</span><input id="${k}iface" class="mono"></label>
        <label id="${k}tunL"><span id="${k}tunT">Tunnel interface</span><input id="${k}tun" class="mono"></label>
        <label id="${k}rgL">Resource group<input id="${k}rg" class="mono"></label>
        <label id="${k}gwL">VPN gateway name<input id="${k}gw" class="mono"></label>
        <label id="${k}locL">Region<input id="${k}loc" class="mono"></label>
        <label id="${k}cmodeL">Connection mode<select id="${k}cmode"><option>Default</option><option>InitiatorOnly</option><option>ResponderOnly</option></select></label>
        <label id="${k}typesL">Bicep types file (required)<input id="${k}types" class="mono" placeholder="./types.bicep"></label>
      </div>
      <p class="hint side-hint" id="${k}vhint"></p>`;
  }

  /* Show only the fields the chosen platform uses. */
  function updateSidePanel(k) {
    const v = TM.vendor(S[k].vendor);
    const f = v.fields;
    if (!v.modes.includes(S[k].mode)) S[k].mode = v.modes[0];
    $(k + "mode").disabled = v.modes.length === 1;
    $(k + "mode").value = S[k].mode;
    $(k + "ifaceL").hidden = !f.iface;
    $(k + "tunL").hidden = !f.tun;
    if (f.iface) $(k + "ifaceT").textContent = f.iface;
    if (f.tun) $(k + "tunT").textContent = f.tun;
    ["rg", "gw", "loc", "cmode", "types"].forEach((x) => { $(k + x + "L").hidden = !f.azure; });
    $(k + "vhint").textContent = v.hint || "";
    $("h" + k).textContent = S[k].name || "Side " + k;
  }

  /* ---------- crypto selects ---------- */

  /* Append "✕ Platform" to options one of the two sides cannot use. */
  function unsupportedBy(field, value) {
    const missing = SIDES.map((k) => TM.vendor(S[k].vendor)).filter((v) => !v.supports[field].includes(value)).map((v) => v.short);
    return missing.length ? "  ✕ " + missing.join(", ") : "";
  }

  function fillSelect(el, list, value) {
    el.innerHTML = list.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("");
    el.value = String(value);
  }

  function renderCrypto() {
    // GCM in ESP carries its own integrity.
    if (isGcm(S.p2enc)) S.p2int = S.p2enc;
    else if (isGcm(S.p2int)) S.p2int = "sha256";

    fillSelect($("p1enc"), ENC.map(([v, l]) => [v, l + unsupportedBy("p1enc", v)]), S.p1enc);
    fillSelect($("p1int"), INT.map(([v, l]) => [v, l + unsupportedBy("p1int", v)]), S.p1int);
    fillSelect($("dh"), DH.map(([v, l]) => [v, l + unsupportedBy("dh", v)]), S.dh);
    fillSelect($("p2enc"), ENC.map(([v, l]) => [v, l + unsupportedBy("p2enc", v)]), S.p2enc);
    fillSelect($("p2int"),
      isGcm(S.p2enc) ? [[S.p2enc, encLabel(S.p2enc) + " (built in)"]] : INT.map(([v, l]) => [v, l + unsupportedBy("p2int", v)]),
      S.p2int);
    $("p2int").disabled = isGcm(S.p2enc);
    fillSelect($("pfs"), PFS.map(([v, l]) => [v, l + (v ? unsupportedBy("pfs", v) : "")]), S.pfs);

    $("p1intLabel").textContent = isGcm(S.p1enc) ? "PRF (GCM provides integrity)" : "Integrity / PRF";
    $("p2hint").textContent = isGcm(S.p2enc)
      ? "GCM provides both encryption and integrity in ESP. Azure requires the same GCM value for IPsec encryption and integrity."
      : "";

    const azure = SIDES.some((k) => S[k].vendor === "azure");
    $("dpdHint").textContent = `Dead peer declared after about ${S.dpdInt * S.dpdRetry} s.` +
      (azure ? ` Azure has no retry count: dpdTimeoutSeconds = interval × retries = ${TM.vendor("azure").dpdTimeout(S)} s.` : "");
  }

  /* ---------- checks and selectors ---------- */

  const SEVERITY_LABEL = { err: "ERROR", warn: "WARNING", info: "INFO", ok: "OK" };
  const SEVERITY_ORDER = { err: 0, warn: 1, ok: 2, info: 3 };

  function renderChecks(R) {
    const list = R.issues.slice().sort((a, b) => SEVERITY_ORDER[a[0]] - SEVERITY_ORDER[b[0]]);
    $("checks").innerHTML = list
      .map(([s, t]) => `<li><span class="sev ${s}">${SEVERITY_LABEL[s]}</span><span>${esc(t)}</span></li>`)
      .join("");

    const errors = list.filter((x) => x[0] === "err").length;
    const warnings = list.filter((x) => x[0] === "warn").length;
    $("checkCount").textContent = `${errors} errors · ${warnings} warnings`;

    const status = $("status");
    status.className = "pill " + (errors ? "err" : warnings ? "warn" : "ok");
    status.textContent = errors
      ? `${errors} ${errors === 1 ? "error" : "errors"}, tunnel will not come up`
      : warnings ? `Matches · ${warnings} ${warnings === 1 ? "warning" : "warnings"}` : "Matches";
  }

  function renderSelectors(R) {
    const { A, B } = R.eff;
    $("tsMode").textContent =
      `A: ${A.mode}${A.narrowed ? " (narrow TS)" : ""} · B: ${B.mode}${B.narrowed ? " (narrow TS)" : ""}`;

    if (!R.selectors) {
      $("tsTable").innerHTML = `
        <thead><tr><th>Side A local</th><th></th><th>Side B local</th></tr></thead>
        <tbody>
          <tr><td class="mono">0.0.0.0/0</td><td>⇄</td><td class="mono">0.0.0.0/0</td></tr>
          <tr><td colspan="3" class="hint">Routes decide the traffic: A routes ${esc(R.B.nets.map((x) => x.text).join(", "))}
            and B routes ${esc(R.A.nets.map((x) => x.text).join(", "))} into the tunnel.</td></tr>
        </tbody>`;
      return;
    }
    const rows = R.selectors
      .map(([a, b], i) => `<tr><td class="mono">${i + 1}</td><td class="mono">${esc(a.text)}</td><td>⇄</td><td class="mono">${esc(b.text)}</td></tr>`)
      .join("");
    $("tsTable").innerHTML = `
      <thead><tr><th>#</th><th>Side A local</th><th></th><th>Side B local</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="4" class="hint">No valid networks.</td></tr>`}</tbody>`;
  }

  /* ---------- recommended baseline ---------- */

  const GRADE_LABEL = { rec: "Recommended", min: "Meets minimum", below: "Below baseline", manual: "Check by hand" };

  function renderBaseline() {
    const { rows, overall } = TM.baseline.evaluate(S);
    const pill = $("baselineStatus");
    pill.className = "pill " + overall;
    pill.textContent = GRADE_LABEL[overall];

    $("baselineTable").innerHTML = `
      <thead><tr><th>Setting</th><th>Your choice</th><th>Guidance</th><th>Grade</th><th>Source</th></tr></thead>
      <tbody>${rows.map((r) => `
        <tr>
          <td>${esc(r.setting)}</td>
          <td class="mono">${esc(r.value)}</td>
          <td>${esc(r.recommendation)}${r.note ? `<span class="baseline-note">${esc(r.note)}</span>` : ""}</td>
          <td><span class="grade ${r.status}">${GRADE_LABEL[r.status]}</span></td>
          <td class="baseline-src">${esc(r.sources.join(", "))}</td>
        </tr>`).join("")}
      </tbody>`;
  }

  const PROFILE_KEYS = ["p1enc", "p1int", "dh", "p2enc", "p2int", "pfs"];

  function applyStrongest() {
    const hint = $("strongestHint");
    const profile = TM.baseline.strongestProfile(S);
    if (!profile) {
      hint.textContent = "No profile works on both platforms without errors. Check the platform choices.";
      return;
    }
    if (PROFILE_KEYS.every((k) => S[k] === profile[k])) {
      hint.textContent = "This is already the strongest profile both sides support.";
      return;
    }
    Object.assign(S, profile);
    update();
    hint.textContent = `Applied: ${encLabel(profile.p1enc)} / ${TM.intLabel(profile.p1int)} / group ${profile.dh} · ESP ${encLabel(profile.p2enc)}` +
      `${isGcm(profile.p2enc) ? "" : " / " + TM.intLabel(profile.p2int)} · PFS group ${profile.pfs}.`;
  }

  /* ---------- go-live checklist ---------- */

  function renderChecklist() {
    $("checklistItems").innerHTML = TM.baseline.CHECKLIST.map(([id, text]) => `
      <li><label><input type="checkbox" id="chk-${id}" data-check="${id}"${S.checklist[id] ? " checked" : ""}><span>${esc(text)}</span></label></li>`).join("");
    updateChecklistCount();
  }

  function updateChecklistCount() {
    const done = TM.baseline.CHECKLIST.filter(([id]) => S.checklist[id]).length;
    $("checklistCount").textContent = `${done} of ${TM.baseline.CHECKLIST.length} done`;
  }

  /* Prefill the "working configuration" issue form with what is on screen. */
  const REPO = "https://github.com/viktormar1337/ipsec-tunnelmatch";

  function reportUrl(R) {
    const va = TM.vendor(S.A.vendor), vb = TM.vendor(S.B.vendor);
    const typeLabel = (e) => (e.mode === "route" ? "Route-based (VTI)" : "Policy-based");
    const settings = TM.nameRows(S).map((r) => `${r[0]}: ${r[1]}  [A: ${r[2]} | B: ${r[3]}]`)
      .concat([`IKE SA lifetime: ${S.p1life} s`, `Child SA lifetime: ${S.p2life} s`, `Baseline: ${GRADE_LABEL[TM.baseline.evaluate(S).overall]}`])
      .join("\n");
    const params = new URLSearchParams({
      template: "working_config.yml",
      title: `[Works]: ${va.short} ↔ ${vb.short}`,
      "side-a-platform": va.label,
      "side-b-platform": vb.label,
      "vpn-type-a": typeLabel(R.eff.A),
      "vpn-type-b": typeLabel(R.eff.B),
      settings,
    });
    return `${REPO}/issues/new?${params}`;
  }

  /* ---------- output tabs ---------- */

  let activeTab = "A";
  let blocks = []; // plain text of each output block, for the copy buttons

  function renderTabs() {
    const tabs = [
      ["A", `Side A · ${TM.vendor(S.A.vendor).short}`],
      ["B", `Side B · ${TM.vendor(S.B.vendor).short}`],
      ["names", "Name mapping"],
    ];
    $("tabs").innerHTML = tabs
      .map(([id, label]) => `<button class="tab" role="tab" type="button" data-tab="${id}" aria-selected="${activeTab === id}">${esc(label)}</button>`)
      .join("");
  }

  function outputBlock(i, title, hint, inner) {
    return `
      <div class="block">
        <div class="block-bar">
          <div><h3>${esc(title)}</h3>${hint ? `<p class="hint">${esc(hint)}</p>` : ""}</div>
          <span class="block-actions"><span class="toast" id="toast${i}" aria-live="polite"></span>
            <button class="btn ghost" type="button" data-copy="${i}">Copy</button></span>
        </div>
        ${inner}
      </div>`;
  }

  function renderOutput(R) {
    if (activeTab === "names") {
      const rows = TM.nameRows(S);
      blocks = [rows.map((r) => r.join("\t")).join("\n")];
      const body = rows.map((r) => `<tr><td>${esc(r[0])}</td>${r.slice(1).map((c) => `<td class="mono">${esc(c)}</td>`).join("")}</tr>`).join("");
      $("outBody").innerHTML = outputBlock(0, "Same choices, spelled the way each platform expects", "", `
        <div class="tbl-wrap flush"><table>
          <thead><tr><th>Parameter</th><th>Neutral</th><th>${esc(TM.vendor(S.A.vendor).short)} (A)</th><th>${esc(TM.vendor(S.B.vendor).short)} (B)</th></tr></thead>
          <tbody>${body}</tbody>
        </table></div>`);
      return;
    }

    const v = TM.vendor(S[activeTab].vendor);
    const valid = R.A.nets.length && R.B.nets.length;
    let result = valid ? v.generate(TM.contextFor(S, activeTab, R)) : "Enter valid networks on both sides to generate configuration.";
    if (typeof result === "string") result = [{ title: v.label, text: result }];

    const eff = R.eff[activeTab];
    const hint = (eff.mode === "route" ? "Route-based" : "Policy-based") + (eff.narrowed ? " with narrow selectors" : "");
    blocks = result.map((b) => b.text);
    $("outBody").innerHTML = result.map((b, i) => outputBlock(i, b.title, i === 0 ? hint : "", `<pre>${esc(b.text)}</pre>`)).join("");
  }

  function copyBlock(button) {
    const i = +button.dataset.copy;
    const toast = $("toast" + i);
    const done = () => { toast.textContent = "Copied"; setTimeout(() => (toast.textContent = ""), 1800); };
    const selectInstead = () => {
      const el = button.closest(".block").querySelector("pre, table");
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      toast.textContent = "Selected, press Ctrl/Cmd+C";
    };
    try { navigator.clipboard.writeText(blocks[i]).then(done, selectInstead); } catch (e) { selectInstead(); }
  }

  /* ---------- sources ---------- */

  function sourceCard(label, s) {
    const pill = s.status.startsWith("Verified") || s.status.startsWith("Checked") ? "ok" : "warn";
    const links = s.links.map(([t, u]) => `<li><a href="${u}" target="_blank" rel="noopener">${esc(t)}</a></li>`).join("");
    return `
      <article class="src">
        <div class="src-head"><strong>${esc(label)}</strong><span class="pill ${pill}">${esc(s.status)}</span></div>
        <p class="used">${esc(s.used)}</p>
        <ul>${links}</ul>
      </article>`;
  }

  function renderSources() {
    const b = TM.baseline.SOURCES;
    $("srcGrid").innerHTML = sourceCard(b.label, b) +
      TM.vendorIds().map((id) => sourceCard(TM.vendor(id).label, TM.vendor(id).sources)).join("");
  }

  /* ---------- update cycle ---------- */

  let R = null;

  function update() {
    SIDES.forEach(updateSidePanel);
    renderCrypto();
    R = TM.analyze(S);
    renderChecks(R);
    renderBaseline();
    $("reportLink").href = reportUrl(R);
    renderSelectors(R);
    renderTabs();
    renderOutput(R);
    save();
  }

  /* ---------- PDF ---------- */

  const PDF_LABEL = "Save parameter sheet (PDF)";
  let downloads = null; // Claude artifact download capability, when running inside Claude

  async function savePdf() {
    const button = $("pdfBtn");
    const errors = R.issues.filter((x) => x[0] === "err").length;
    const say = (t) => { $("status").textContent = t; setTimeout(update, 2500); };

    if (!window.jspdf) return say("The PDF library did not load");

    // Ask for a second click when the configuration still has errors.
    if (errors && !button.dataset.confirm) {
      button.dataset.confirm = "1";
      button.textContent = `${errors} ${errors === 1 ? "error" : "errors"} left, click again to save anyway`;
      setTimeout(() => { delete button.dataset.confirm; button.textContent = PDF_LABEL; }, 4000);
      return;
    }
    delete button.dataset.confirm;
    button.textContent = PDF_LABEL;

    const filename = `IPsec-${slug(S.tunnelName)}.pdf`;
    const pdf = TM.buildPdf(S, R, TM.baseline.evaluate(S));

    if (!downloads && window.claude && window.claude.use) {
      try { downloads = await window.claude.use("downloads"); } catch (e) { downloads = null; }
    }

    if (downloads) {
      try {
        await downloads.save({ filename, data: new Blob([pdf], { type: "application/pdf" }) });
        say("PDF saved");
      } catch (e) {
        if (!e || e.code !== "declined") say("Could not save the PDF" + (e && e.code ? " (" + e.code + ")" : ""));
      }
      return;
    }

    // Plain browser (GitHub Pages, local file): ordinary download.
    try {
      const url = URL.createObjectURL(new Blob([pdf], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      say("PDF saved");
    } catch (e) {
      say("Could not save the PDF");
    }
  }

  /* ---------- wiring ---------- */

  function bind() {
    ["tunnelName", "author"].forEach((id) => {
      $(id).value = S[id];
      $(id).addEventListener("input", () => { S[id] = $(id).value; update(); });
    });
    ["p1life", "dpdInt", "dpdRetry", "p2life", "p2kb"].forEach((id) => {
      $(id).value = S[id];
      $(id).addEventListener("input", () => { S[id] = +$(id).value; update(); });
    });
    ["p1enc", "p1int", "p2enc", "p2int"].forEach((id) =>
      $(id).addEventListener("change", () => { S[id] = $(id).value; update(); }));
    ["dh", "pfs"].forEach((id) =>
      $(id).addEventListener("change", () => { S[id] = +$(id).value; update(); }));

    SIDES.forEach((k) => {
      SIDE_FIELDS.forEach((f) => {
        const el = $(k + f);
        el.value = S[k][f] || "";
        el.addEventListener(SELECT_FIELDS.includes(f) ? "change" : "input", () => { S[k][f] = el.value; update(); });
      });
      const vendorSelect = $(k + "vendor");
      vendorSelect.value = S[k].vendor;
      vendorSelect.addEventListener("change", () => {
        const v = TM.vendor(vendorSelect.value);
        S[k].vendor = v.id;
        S[k].iface = v.defaults.iface || "";
        S[k].tun = v.defaults.tun || "";
        $(k + "iface").value = S[k].iface;
        $(k + "tun").value = S[k].tun;
        update();
      });
    });

    $("tabs").addEventListener("click", (e) => {
      const tab = e.target.closest(".tab");
      if (!tab) return;
      activeTab = tab.dataset.tab;
      renderTabs();
      renderOutput(R);
    });
    $("outBody").addEventListener("click", (e) => {
      const button = e.target.closest("[data-copy]");
      if (button) copyBlock(button);
    });
    $("pdfBtn").addEventListener("click", savePdf);
    $("strongestBtn").addEventListener("click", applyStrongest);
    $("checklistItems").addEventListener("change", (e) => {
      const id = e.target.dataset.check;
      if (!id) return;
      S.checklist[id] = e.target.checked;
      updateChecklistCount();
      save();
    });
  }

  SIDES.forEach((k) => { $("side" + k).innerHTML = sidePanel(k); });
  renderSources();
  renderChecklist();
  bind();
  update();
})();
