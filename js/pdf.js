/*
 * IPsec Tunnelmatch – PDF parameter sheet (jsPDF + jsPDF-AutoTable)
 *
 * TM.buildPdf(S, R, baseline) returns the PDF as an ArrayBuffer. The sheet is in English
 * because it usually goes to an external party. The pre-shared key is never in it.
 */
(function () {
  "use strict";
  const { isGcm } = TM;

  const ACCENT = [11, 106, 134];
  const INK = [22, 32, 46];
  const MUTED = [88, 99, 116];
  const LINE = [213, 219, 228];
  const MARGIN = 40;

  const modeText = (e) =>
    (e.mode === "route" ? "Route-based" : "Policy-based") +
    (e.narrowed ? " (narrowed selectors)" : "") +
    (e.switched ? " (policy to match peer)" : "");

  function notesFor(S, R) {
    const { eff } = R;
    const notes = [];
    if (eff.A.narrowed || eff.B.narrowed)
      notes.push(`Site ${eff.A.narrowed ? "A" : "B"} is route-based and narrows its traffic selectors to the subnet pairs above to match the policy-based peer.`);
    if (eff.A.switched || eff.B.switched)
      notes.push(`Site ${eff.A.switched ? "A" : "B"} is configured policy-based so its selectors match the peer.`);
    ["A", "B"].forEach((k) => {
      const v = TM.vendor(S[k].vendor);
      if (v.pdfNote) v.pdfNote(S, eff[k]).forEach((n) => { if (!notes.includes(n)) notes.push(n); });
    });
    if (!R.selectors)
      notes.push("Both sides are route-based (any/any selectors); each side routes the remote networks into its tunnel interface.");
    notes.push("The pre-shared key is not part of this document. Agree it through a separate secure channel and enter it directly on each device.");
    notes.push("Either side may initiate. UDP 500 and UDP 4500 (NAT-T) must be allowed between the public IPs.");
    return notes;
  }

  const GRADE = { rec: "Recommended", min: "Meets minimum", below: "Below baseline", manual: "Check by hand" };

  function buildPdf(S, R, baseline) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const W = doc.internal.pageSize.getWidth();
    const H = doc.internal.pageSize.getHeight();

    /* header band */
    doc.setFillColor(...ACCENT);
    doc.rect(0, 0, W, 64, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(17);
    doc.text("IPsec Site-to-Site Parameter Sheet", MARGIN, 30);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    const today = new Date().toISOString().slice(0, 10);
    doc.text(`${S.tunnelName || "Tunnel"}   |   ${today}${S.author ? "   |   Prepared by " + S.author : ""}`, MARGIN, 48);

    const base = {
      theme: "grid",
      styles: { font: "helvetica", fontSize: 9, cellPadding: 4, textColor: INK, lineColor: LINE },
      headStyles: { fillColor: ACCENT, textColor: 255, fontStyle: "bold" },
      margin: { left: MARGIN, right: MARGIN },
      columnStyles: { 0: { fontStyle: "bold", cellWidth: 120 } },
    };
    const table = (opts) => doc.autoTable(Object.assign({}, base, opts));
    const next = () => doc.lastAutoTable.finalY + 16;

    const va = TM.vendor(S.A.vendor), vb = TM.vendor(S.B.vendor);
    const rows = TM.nameRows(S); // 0 p1enc, 1 p1int, 2 dh, 3 p2enc, 4 p2int, 5 pfs, 6 dpd
    const cells = (i) => [rows[i][1], rows[i][2], rows[i][3]];

    table({
      startY: 84,
      head: [["Endpoint", "Site A", "Site B"]],
      body: [
        ["Site / organisation", S.A.name, S.B.name],
        ["Platform", va.label, vb.label],
        ["Public IP (peer address)", S.A.ip, S.B.ip],
        ["Local networks", R.A.nets.map((x) => x.text).join("\n"), R.B.nets.map((x) => x.text).join("\n")],
        ["VPN type", modeText(R.eff.A), modeText(R.eff.B)],
      ],
    });

    table({
      startY: next(),
      head: [["Phase 1 (IKE)", "Agreed value", va.short + " naming", vb.short + " naming"]],
      body: [
        ["IKE version", "IKEv2", "", ""],
        ["Authentication", "Pre-shared key (exchanged out-of-band, never in this document)", "", ""],
        ["Encryption", ...cells(0)],
        [isGcm(S.p1enc) ? "PRF (GCM)" : "Integrity", ...cells(1)],
        ["DH group", ...cells(2)],
        ["SA lifetime", S.p1life + " s", "", ""],
        ["Dead peer detection", `Interval ${S.dpdInt} s, ${S.dpdRetry} retries`, rows[6][2], rows[6][3]],
      ],
    });

    table({
      startY: next(),
      head: [["Phase 2 (IPsec)", "Agreed value", va.short + " naming", vb.short + " naming"]],
      body: [
        ["Protocol / mode", "ESP, tunnel mode", "", ""],
        ["Encryption", ...cells(3)],
        ["Integrity", isGcm(S.p2enc) ? "Provided by GCM" : rows[4][1], rows[4][2], rows[4][3]],
        ["PFS group", S.pfs ? "Group " + S.pfs : "None", rows[5][2], rows[5][3]],
        ["SA lifetime", S.p2life + " s" + (S.p2kb ? " / " + S.p2kb + " KB" : ""), "", ""],
      ],
    });

    table({
      startY: next(),
      head: [["#", "Site A local", "Site B local"]],
      body: R.selectors
        ? R.selectors.map(([a, b], i) => [String(i + 1), a.text, b.text])
        : [["-", "0.0.0.0/0 (route-based)", "0.0.0.0/0 (route-based)"]],
      columnStyles: { 0: { cellWidth: 30 } },
    });

    if (baseline) {
      table({
        startY: next(),
        head: [["Baseline (NIST, RFC 8247, NSA, BSI)", "Agreed value", "Guidance", "Grade: " + GRADE[baseline.overall]]],
        body: baseline.rows.map((r) => [r.setting, r.value, r.recommendation, GRADE[r.status]]),
      });
    }

    table({
      startY: next(),
      head: [["Go-live checklist", "Done"]],
      body: TM.baseline.CHECKLIST.map(([id, text]) => [text, S.checklist && S.checklist[id] ? "Yes" : "No"]),
      columnStyles: { 0: { cellWidth: "auto" }, 1: { cellWidth: 50, halign: "center" } },
    });

    table({
      startY: next(),
      head: [["Notes"]],
      body: notesFor(S, R).map((n) => [n]),
      headStyles: { fillColor: MUTED, textColor: 255 },
      columnStyles: {},
    });

    /* footer on every page */
    const pages = doc.getNumberOfPages();
    for (let i = 1; i <= pages; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(...MUTED);
      doc.text("Generated with IPsec Tunnelmatch. Verify against device documentation and lab-test before production.", MARGIN, H - 22);
      doc.text(`${i}/${pages}`, W - MARGIN, H - 22, { align: "right" });
    }
    return doc.output("arraybuffer");
  }

  TM.buildPdf = buildPdf;
})();
