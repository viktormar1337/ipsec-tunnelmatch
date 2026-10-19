/*
 * IPsec Tunnelmatch – recommended baseline and go-live checklist
 *
 * Grades the chosen crypto profile against published guidance:
 *   rec    recommended by current guidance
 *   min    meets the minimum, but stronger options exist
 *   below  below the baseline (weak, deprecated or discouraged)
 *   manual cannot be checked here; confirm by hand
 *
 * Sources (checked 2026-10-19): NIST SP 800-77 Rev. 1, RFC 8247,
 * NSA "Configuring IPsec VPNs" (2020), NSA CSfC IPsec selections (2026-08-04),
 * BSI TR-02102-3 (2026-01), EU PQC roadmap (2025-06-23).
 */
(function () {
  "use strict";
  const { isGcm, encLabel, intLabel } = TM;

  /* Approximate classical security strength in bits, used to compare DH groups. */
  const DH_STRENGTH = { 2: 80, 5: 96, 14: 112, 24: 112, 15: 128, 19: 128, 20: 192, 21: 256 };

  const SRC = {
    nist: "NIST SP 800-77r1",
    rfc: "RFC 8247",
    nsa: "NSA 2020",
    csfc: "NSA CSfC 2026",
    bsi: "BSI TR-02102-3",
    eu: "EU PQC roadmap",
  };

  /* Each rule returns { status, note } for the current state. */
  const RULES = [
    {
      setting: "IKE version",
      value: () => "IKEv2",
      recommendation: "IKEv2 only",
      sources: [SRC.nist, SRC.bsi, SRC.nsa],
      grade: () => ({ status: "rec" }),
    },
    {
      setting: "Phase 1 encryption",
      value: (S) => encLabel(S.p1enc),
      recommendation: "AES-256 (GCM or CBC)",
      sources: [SRC.nsa, SRC.nist],
      grade: (S) =>
        S.p1enc === "3des" ? { status: "below", note: "3DES is legacy." }
        : S.p1enc.startsWith("aes256") ? { status: "rec" }
        : { status: "min", note: "AES-128/192 is allowed; AES-256 is recommended." },
    },
    {
      setting: "Phase 1 integrity / PRF",
      value: (S) => intLabel(S.p1int),
      recommendation: "SHA-384 or SHA-512 (SHA-256 minimum)",
      sources: [SRC.nsa, SRC.rfc, SRC.nist],
      grade: (S) =>
        ["sha1", "md5"].includes(S.p1int) ? { status: "below", note: "SHA-1 and MD5 are deprecated." }
        : S.p1int === "sha256" ? { status: "min" }
        : { status: "rec" },
    },
    {
      setting: "DH group",
      value: (S) => "Group " + S.dh,
      recommendation: "19, 20 or 21 (14 minimum). Avoid 1, 2, 5, 24",
      sources: [SRC.bsi, SRC.nsa, SRC.rfc],
      grade: (S) =>
        [2, 5, 24].includes(S.dh) ? { status: "below", note: S.dh === 24 ? "RFC 8247: SHOULD NOT." : "Too weak." }
        : S.dh === 14 ? { status: "min" }
        : { status: "rec" },
    },
    {
      setting: "Phase 2 encryption",
      value: (S) => encLabel(S.p2enc),
      recommendation: "AES-256-GCM",
      sources: [SRC.bsi, SRC.csfc, SRC.nist],
      grade: (S) =>
        S.p2enc === "3des" ? { status: "below", note: "3DES is legacy." }
        : S.p2enc === "aes256gcm" ? { status: "rec" }
        : { status: "min", note: "AES-256-GCM is recommended where both sides support it." },
    },
    {
      setting: "Phase 2 integrity",
      value: (S) => (isGcm(S.p2enc) ? "Built into GCM" : intLabel(S.p2int)),
      recommendation: "GCM, or SHA-256 or stronger",
      sources: [SRC.nist, SRC.rfc],
      grade: (S) =>
        isGcm(S.p2enc) ? { status: "rec" }
        : ["sha1", "md5"].includes(S.p2int) ? { status: "below", note: "SHA-1 and MD5 are deprecated." }
        : S.p2int === "sha256" ? { status: "min" }
        : { status: "rec" },
    },
    {
      setting: "PFS",
      value: (S) => (S.pfs ? "Group " + S.pfs : "Off"),
      recommendation: "On, as strong as the phase 1 group",
      sources: [SRC.nist],
      grade: (S) =>
        !S.pfs ? { status: "below", note: "Turn PFS on." }
        : [2, 5, 24].includes(S.pfs) ? { status: "below", note: "Weak PFS group." }
        : (DH_STRENGTH[S.pfs] || 0) < (DH_STRENGTH[S.dh] || 0) ? { status: "min", note: "Weaker than the phase 1 group." }
        : { status: "rec" },
    },
    {
      setting: "IKE SA lifetime",
      value: (S) => S.p1life + " s",
      recommendation: "24 hours or less",
      sources: [SRC.nist, SRC.csfc],
      grade: (S) => (S.p1life <= 86400 ? { status: "rec" } : { status: "below", note: "Longer than 24 h." }),
    },
    {
      setting: "Child SA lifetime",
      value: (S) => S.p2life + " s",
      recommendation: "8 hours or less",
      sources: [SRC.nist, SRC.csfc],
      grade: (S) => (S.p2life <= 28800 ? { status: "rec" } : { status: "below", note: "Longer than 8 h." }),
    },
    {
      setting: "Authentication",
      value: () => "Pre-shared key",
      recommendation: "Certificates preferred. PSK: 32+ random characters, out-of-band",
      sources: [SRC.bsi, SRC.nist, SRC.csfc],
      grade: () => ({ status: "manual", note: "Confirm the key length and how it was shared." }),
    },
    {
      setting: "Post-quantum",
      value: () => "Not configured",
      recommendation: "Plan ML-KEM hybrid key exchange (RFC 9370)",
      sources: [SRC.eu, SRC.bsi],
      grade: () => ({ status: "manual", note: "EU: high-risk sectors, including finance, by 2030." }),
    },
  ];

  function evaluate(S) {
    const rows = RULES.map((r) => Object.assign({ setting: r.setting, value: r.value(S), recommendation: r.recommendation, sources: r.sources }, r.grade(S)));
    const graded = rows.filter((r) => r.status !== "manual");
    const overall = graded.some((r) => r.status === "below") ? "below"
      : graded.some((r) => r.status === "min") ? "min" : "rec";
    return { rows, overall };
  }

  /*
   * Strongest profile that both platforms accept: try every combination in
   * order of preference, keep those without algorithm errors, and pick the one
   * with the best baseline grade. Values that depend on firmware version are
   * avoided when a version-independent profile exists.
   */
  const CANDIDATES = {
    p1enc: ["aes256gcm", "aes256", "aes128gcm", "aes128"],
    p1int: ["sha384", "sha512", "sha256"],
    dh: [20, 19, 21, 15, 14],
    p2enc: ["aes256gcm", "aes256", "aes128gcm", "aes128"],
    p2int: ["sha384", "sha512", "sha256"],
  };
  const POINTS = { rec: 2, min: 1, below: -10, manual: 0 };

  /* Compare two keys element by element; true when a beats b. */
  function better(a, b) {
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] > b[i];
    return false;
  }

  function strongestProfile(S) {
    let best = null;
    const consider = (profile) => {
      const trial = Object.assign({}, S, profile);
      const issues = TM.analyze(trial).issues;
      if (issues.some(([sev, , cat]) => sev === "err" && cat === "crypto")) return;
      const versionDependent = issues.some(([, , cat]) => cat === "verify") ? 1 : 0;
      const softCrypto = issues.filter(([sev, , cat]) => sev === "warn" && cat === "crypto").length;
      const score = evaluate(trial).rows.reduce((sum, r) => sum + POINTS[r.status], 0);
      // Prefer: no version-dependent values, then highest grade, then fewest soft warnings.
      const key = [-versionDependent, score, -softCrypto];
      if (!best || better(key, best.key)) best = { profile, key }; // ties keep the earlier, preferred candidate
    };

    CANDIDATES.p1enc.forEach((p1enc) =>
      CANDIDATES.p1int.forEach((p1int) =>
        CANDIDATES.dh.forEach((dh) =>
          CANDIDATES.p2enc.forEach((p2enc) => {
            const p2ints = isGcm(p2enc) ? [p2enc] : CANDIDATES.p2int;
            p2ints.forEach((p2int) => consider({ p1enc, p1int, dh, p2enc, p2int, pfs: dh }));
          }))));

    return best && best.profile;
  }

  /* Go-live checklist; ticks are stored per browser with the rest of the form. */
  const CHECKLIST = [
    ["psk", "Pre-shared key is 32+ random characters, unique to this tunnel, and was shared out-of-band (or certificates are used)."],
    ["proposals", "Only the agreed proposal is configured on both sides; vendor defaults and unused proposals are removed."],
    ["exposure", "UDP 500, UDP 4500 and ESP are allowed only from the peer's public IP."],
    ["firmware", "Both sides run current firmware that supports the chosen algorithms, and the versions are noted."],
    ["negotiated", "After go-live, the negotiated IKE and child SAs were checked on both sides and match this sheet."],
    ["rekey", "The tunnel survived a phase 2 rekey (traffic kept flowing past the child SA lifetime)."],
    ["dpd", "Dead peer detection or failover was tested by taking one side down."],
    ["pq", "The post-quantum (ML-KEM hybrid) roadmap for both platforms is noted."],
  ];

  const SOURCES = {
    label: "Recommended baseline",
    status: "Checked 2026-10-19",
    used: "Baseline grades and go-live checklist: IKEv2 only, AES-256(-GCM), SHA-256 minimum (SHA-384 preferred), DH 14 minimum (19/20/21 preferred, not 1/2/5/24), PFS on, IKE SA ≤ 24 h, child SA ≤ 8 h, long random PSK or certificates, post-quantum planning.",
    links: [
      ["NIST SP 800-77 Rev. 1: Guide to IPsec VPNs (2020)", "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-77r1.pdf"],
      ["RFC 8247: Algorithm requirements for IKEv2", "https://www.rfc-editor.org/rfc/rfc8247"],
      ["NSA: Configuring IPsec Virtual Private Networks (2020)", "https://media.defense.gov/2020/Jul/02/2002355501/-1/-1/0/CONFIGURING_IPSEC_VIRTUAL_PRIVATE_NETWORKS_2020_07_01_FINAL_RELEASE.PDF"],
      ["NSA CSfC: Selections for IPsec VPN Client (2026-08-04)", "https://www.nsa.gov/Portals/75/documents/CSfC%20Selections%20Updates%202026/CSfC_Selections_for_IPsec_VPN_Client-2026-08-04.pdf"],
      ["BSI TR-02102-3: IPsec and IKEv2 (2026-01)", "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-3.pdf"],
      ["EU PQC roadmap summary (2025-06-23)", "https://postquantum.com/quantum-policy/eu-pqc-roadmap/"],
      ["IETF draft: ML-KEM in IKEv2", "https://datatracker.ietf.org/doc/draft-ietf-ipsecme-ikev2-mlkem/"],
    ],
  };

  TM.baseline = { evaluate, strongestProfile, CHECKLIST, SOURCES };
})();
