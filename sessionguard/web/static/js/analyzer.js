/**
 * SessionGuard Interactive Security Console Frontend Engine
 */
document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const jwtInput = document.getElementById("jwt-input");
  const targetUrlInput = document.getElementById("target-url-input");
  const btnRunAudit = document.getElementById("btn-run-audit");
  const btnClear = document.getElementById("btn-clear");
  const btnPasteClipboard = document.getElementById("btn-paste-clipboard");

  const targetStatusBadge = document.getElementById("target-status-badge");
  const targetStatusText = document.getElementById("target-status-text");

  const emptyState = document.getElementById("empty-state");
  const loadingState = document.getElementById("loading-state");
  const resultsSection = document.getElementById("results-section");

  // Executive summary elements
  const riskScoreBox = document.getElementById("risk-score-box");
  const scoreValue = document.getElementById("score-value");
  const scoreBadgeText = document.getElementById("score-badge-text");
  const verdictTitle = document.getElementById("verdict-title");
  const verdictDesc = document.getElementById("verdict-desc");
  const statTotal = document.getElementById("stat-total");
  const statFailed = document.getElementById("stat-failed");
  const statPassed = document.getElementById("stat-passed");
  const statSpeed = document.getElementById("stat-speed");
  const metaPreview = document.getElementById("meta-preview");

  // Cards & Tabs
  const checksCardsContainer = document.getElementById("checks-cards-container");
  const jsonPayloadEl = document.getElementById("json-payload");
  const standardsTableBody = document.getElementById("standards-table-body");
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  // Export buttons
  const btnPrintReport = document.getElementById("btn-print-report");
  const btnCopyPayload = document.getElementById("btn-copy-payload");


  let currentReportData = null;

  // 1. Initial Target App Connectivity Check
  async function checkTargetStatus() {
    const targetUrl = targetUrlInput.value.trim();
    
    if (!targetUrl) {
      targetStatusBadge.className = "target-badge offline";
      targetStatusText.textContent = "Target Server: No URL";
      return;
    }
    
    targetStatusText.textContent = "Checking...";
    targetStatusBadge.className = "target-badge checking";
    
    try {
      const res = await fetch(`/api/target-status?target_url=${encodeURIComponent(targetUrl)}`);
      const data = await res.json();
      if (data.online) {
        targetStatusBadge.className = "target-badge online";
        targetStatusText.textContent = "Target Server: Reachable";
      } else {
        targetStatusBadge.className = "target-badge offline";
        targetStatusText.textContent = "Target Server: Offline";
      }
    } catch {
      targetStatusBadge.className = "target-badge offline";
      targetStatusText.textContent = "Target Server: Offline";
    }
  }

  checkTargetStatus();
  setInterval(checkTargetStatus, 6000);
  
  // Re-check instantly when the user changes the target URL
  targetUrlInput.addEventListener("change", checkTargetStatus);

  // 2. Paste and Clear
  btnPasteClipboard.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        jwtInput.value = text.trim();
      }
    } catch {
      const pasted = prompt("Paste your JWT token here:");
      if (pasted) jwtInput.value = pasted.trim();
    }
  });

  btnClear.addEventListener("click", () => {
    jwtInput.value = "";
    resultsSection.style.display = "none";
    loadingState.style.display = "none";
    emptyState.style.display = "block";
    currentReportData = null;
  });

  // 4. Tab Navigation
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabPanes.forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const targetTab = document.getElementById(btn.getAttribute("data-tab"));
      if (targetTab) targetTab.classList.add("active");
    });
  });

  // 5. Run Security Audit
  async function runAudit() {
    const rawToken = jwtInput.value.trim();
    if (!rawToken) {
      alert("Please paste a JWT token to analyze.");
      jwtInput.focus();
      return;
    }

    const targetUrl = targetUrlInput.value.trim() || null;

    // Show loading state
    emptyState.style.display = "none";
    resultsSection.style.display = "none";
    loadingState.style.display = "block";
    
    // Inject dynamic terminal for suspense
    loadingState.innerHTML = `
      <div class="scanner-radar"></div>
      <h4>Executing Multi-Vector Security Checks...</h4>
      <div id="scan-steps" style="text-align: left; margin: 1.5rem auto; max-width: 450px; font-family: var(--font-mono); font-size: 0.85rem; color: var(--accent-cyan); line-height: 1.6;"></div>
    `;

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: rawToken, target_url: targetUrl })
      });

      const json = await res.json();

      if (!res.ok || json.error) {
        loadingState.style.display = "none";
        alert(json.error || "Security audit failed.");
        emptyState.style.display = "block";
        return;
      }

      currentReportData = json.report;
      
      // Save report and redirect to dedicated report page
      sessionStorage.setItem("sessionguard_report", JSON.stringify(json.report));
      window.location.href = "/report";

    } catch (err) {
      loadingState.style.display = "none";
      emptyState.style.display = "block";
      alert("Network or server error during audit: " + err.message);
    }
  }

  btnRunAudit.addEventListener("click", runAudit);


  // 7. Render Full Audit Report
  function renderAuditReport(report) {
    const meta = report.token_metadata || {};

    // 7.1 Risk Score Badge
    const score = report.overall_score || 1;
    scoreValue.textContent = score;

    riskScoreBox.className = "risk-score-box";
    if (score >= 9) {
      riskScoreBox.classList.add("score-critical");
      scoreBadgeText.textContent = "CRITICAL RISK";
    } else if (score >= 6) {
      riskScoreBox.classList.add("score-high");
      scoreBadgeText.textContent = "HIGH RISK";
    } else if (score >= 4) {
      riskScoreBox.classList.add("score-medium");
      scoreBadgeText.textContent = "MEDIUM RISK";
    } else {
      riskScoreBox.classList.add("score-low");
      scoreBadgeText.textContent = "LOW RISK (HARDENED)";
    }

    // 7.2 Verdict Text
    if (score >= 9) {
      verdictTitle.textContent = "Complete Account Takeover Possible";
    } else if (score >= 6) {
      verdictTitle.textContent = "Persistent Session Hijacking Window";
    } else {
      verdictTitle.textContent = "Hardened & Defended Session Posture";
    }
    verdictDesc.textContent = report.hijack_verdict || "No issues found.";

    // 7.3 Stats Grid
    statTotal.textContent = report.total_checks;
    statFailed.textContent = report.failed_count;
    statPassed.textContent = report.passed_count;
    metaPreview.textContent = report.raw_token_preview || "N/A";

    // Speed estimation from weak secret check
    const crackCheck = (report.checks || []).find(c => c.check_id === "weak_secret");
    if (crackCheck && crackCheck.details && crackCheck.details.speed_keys_per_sec) {
      statSpeed.textContent = `${Math.round(crackCheck.details.speed_keys_per_sec / 1000)}K keys/s`;
    } else {
      statSpeed.textContent = "35K keys/s";
    }

    // 7.4 Render Security Check Cards
    checksCardsContainer.innerHTML = "";
    (report.checks || []).forEach(check => {
      const card = document.createElement("div");
      card.className = `check-card ${check.passed ? "check-passed" : "check-failed"}`;

      const statusBadge = check.passed
        ? `<span class="badge-status badge-pass">PASS</span>`
        : `<span class="badge-status badge-fail">FAIL: ${check.severity}</span>`;

      const scoreBadge = check.passed
        ? `<span class="check-score-pill">Score: 1/9</span>`
        : `<span class="check-score-pill">Score: ${check.score}/9</span>`;

      card.innerHTML = `
        <div class="check-header">
          <div class="check-title-wrap">
            ${statusBadge}
            <h4 class="check-name">${escapeHtml(check.title)}</h4>
          </div>
          ${scoreBadge}
        </div>
        <p class="check-body">${escapeHtml(check.description)}</p>
        <div class="check-standards">
          <span>Standards: ${escapeHtml(check.cwe)} | ${escapeHtml(check.owasp)}</span>
        </div>
        ${check.remediation ? `
          <div class="check-remediation">
            <span class="remediation-label">💡 Recommended Remediation:</span>
            <span>${escapeHtml(check.remediation)}</span>
          </div>
        ` : ""}
      `;
      checksCardsContainer.appendChild(card);
    });

    // 7.5 Decoded Claims Tab
    document.getElementById("meta-alg").innerHTML = `<span class="badge badge-accent">${escapeHtml(meta.algorithm || "N/A")}</span>`;
    document.getElementById("meta-typ").textContent = meta.type || "JWT";
    document.getElementById("meta-sub").textContent = meta.subject || "Anonymous";
    document.getElementById("meta-role").innerHTML = `<span class="badge badge-role">${escapeHtml(meta.role || "None")}</span>`;
    document.getElementById("meta-iat").textContent = meta.issued_at || "Not Specified";
    document.getElementById("meta-exp").textContent = meta.expires_at || "None (Indefinite)";
    document.getElementById("meta-total-life").textContent = meta.total_lifetime || "Unknown";
    document.getElementById("meta-remaining").textContent = meta.remaining_time || "N/A";

    jsonPayloadEl.textContent = JSON.stringify(meta.payload || {}, null, 2);

    // 7.6 Standards Compliance Table
    renderStandardsTable(report);
  }

  function renderStandardsTable(report) {
    const checks = report.checks || [];
    const rows = [
      {
        std: "OWASP Top 10",
        cat: "A07:2021",
        req: "Identification & Authentication Failures",
        finding: report.failed_count > 0 ? "Session token contains exploitable authentication flaws." : "Authentication parameters conform to best practices.",
        pass: report.failed_count === 0
      },
      {
        std: "OWASP ASVS",
        cat: "V3.5",
        req: "Token-based Session Management",
        finding: (checks.find(c => c.check_id === "alg_none")?.passed) ? "Cryptographic signature enforcement strictly verified." : "Server allows unsigned 'alg:none' tokens.",
        pass: checks.find(c => c.check_id === "alg_none")?.passed ?? true
      },
      {
        std: "OWASP ASVS",
        cat: "V3.3",
        req: "Session Lifetime & Expiration",
        finding: (checks.find(c => c.check_id === "expiration")?.passed) ? "Token expires in <= 1 hour (15-30m recommended)." : "Excessive token validity window (exceeds 48 hours).",
        pass: checks.find(c => c.check_id === "expiration")?.passed ?? true
      },
      {
        std: "MITRE CWE",
        cat: "CWE-798",
        req: "Hard-coded / Trivial Credentials",
        finding: (checks.find(c => c.check_id === "weak_secret")?.passed) ? "HMAC secret resisted offline dictionary attacks." : "Trivial signing secret cracked in milliseconds.",
        pass: checks.find(c => c.check_id === "weak_secret")?.passed ?? true
      },
      {
        std: "MITRE CWE",
        cat: "CWE-347",
        req: "Improper Verification of Cryptographic Signature",
        finding: (checks.find(c => c.check_id === "alg_none")?.passed) ? "Unsigned tokens correctly rejected with 401 Unauthorized." : "Unsigned forged tokens accepted by protected endpoints.",
        pass: checks.find(c => c.check_id === "alg_none")?.passed ?? true
      }
    ];

    standardsTableBody.innerHTML = rows.map(r => `
      <tr>
        <td><strong>${r.std}</strong></td>
        <td><code>${r.cat}</code></td>
        <td>${r.req}</td>
        <td>${r.finding}</td>
        <td>
          <span class="badge-status ${r.pass ? 'badge-pass' : 'badge-fail'}">
            ${r.pass ? 'COMPLIANT' : 'NON-COMPLIANT'}
          </span>
        </td>
      </tr>
    `).join("");
  }

  // 8. Copy Payload JSON
  btnCopyPayload.addEventListener("click", () => {
    const jsonText = jsonPayloadEl.textContent;
    if (jsonText) {
      navigator.clipboard.writeText(jsonText).then(() => {
        const originalText = btnCopyPayload.textContent;
        btnCopyPayload.textContent = "✓ Copied!";
        setTimeout(() => { btnCopyPayload.textContent = originalText; }, 2000);
      });
    }
  });


  // 10. Print / Save PDF
  btnPrintReport.addEventListener("click", () => {
    window.print();
  });

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
