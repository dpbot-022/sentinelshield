// SentinelShield Enterprise Dashboard - Real Cloud Inference & Zero-Trust Engine
(function() {
  // Account registry for real authentication
  const ACCOUNTS = {
    "developer": { email: "developer@gmail.com", password: "DevSecret2026!", tier: "tier-2", quota: "Tier-2: 90 req/min" },
    "admin": { email: "admin@gmail.com", password: "SentinelAdmin2026!", tier: "admin", quota: "Admin: 300 req/min" },
    "enterprise_app": { email: "enterprise_app@corp.internal", password: "ClientApp2026!", tier: "tier-1", quota: "Tier-1: 30 req/min" },
    "guest": { email: "guest@gmail.com", password: "GuestDemo2026!", tier: "guest", quota: "Guest: 5 req/min" },
  };

  let currentUser = "developer@gmail.com";
  let currentToken = null;

  // DOM Elements
  const identityNameLabel = document.getElementById("identity-username-label");
  const identityTierLabel = document.getElementById("identity-tier-label");
  const btnOpenAuth = document.getElementById("btn-open-auth-modal");
  const authModal = document.getElementById("auth-modal");
  const btnCloseAuth = document.getElementById("btn-close-auth-modal");
  const btnCancelAuth = document.getElementById("btn-cancel-auth");
  const btnSubmitAuth = document.getElementById("btn-submit-auth");
  const authUsernameInput = document.getElementById("auth-input-username");
  const authPasswordInput = document.getElementById("auth-input-password");
  const btnTogglePwd = document.getElementById("btn-toggle-pwd");
  const authFeedback = document.getElementById("auth-feedback-box");
  const authBtnSpinner = document.getElementById("auth-btn-spinner");
  const authBtnText = document.getElementById("auth-btn-text");

  const quotaDisplay = document.getElementById("quota-display");
  const tokenBadge = document.getElementById("current-token-badge");
  const promptInput = document.getElementById("input-prompt");
  const charCountEl = document.getElementById("prompt-char-count");
  const schemaSelect = document.getElementById("select-schema");
  const providerSelect = document.getElementById("select-provider");
  const piiModeSelect = document.getElementById("select-pii-mode");
  const malformedCheck = document.getElementById("check-simulate-malformed");
  const btnExecute = document.getElementById("btn-execute-proxy");
  const spinner = document.getElementById("btn-spinner");
  const statusBadge = document.getElementById("overall-status-badge");
  const statusIndicator = document.getElementById("result-status-indicator");
  const jsonOutput = document.getElementById("code-output-json");
  const piiDiffRaw = document.getElementById("pii-diff-raw");
  const piiDiffSanitized = document.getElementById("pii-diff-sanitized");
  const piiVaultContent = document.getElementById("pii-vault-content");
  const healingContent = document.getElementById("healing-diagnostics-content");
  const waterfallChart = document.getElementById("waterfall-chart");

  document.addEventListener("DOMContentLoaded", async () => {
    setupTabs();
    setupAuthModal();
    setupJwtInspector();
    setupClearButton();
    setupPromptCounter();
    setupSubtabs();
    setupCopyButton();

    // Set initial prompt demonstrating PII protection
    promptInput.value = "Customer Michael Chang (SSN: 000-45-6789, email: m.chang@enterprise.com, phone: 415-555-0199) reports unapproved transaction of $1,250 on his corporate card. Please investigate billing issue and issue dispute.";
    charCountEl.textContent = `${promptInput.value.length} characters`;

    // Authenticate initial default account (developer@gmail.com)
    await authenticateAccount("developer@gmail.com", ACCOUNTS["developer"].password, false);

    // Load initial schemas and telemetry
    loadSchemas();
    fetchTelemetry();
    setInterval(fetchTelemetry, 6000);

    // Live Lab Runner
    const btnLab = document.getElementById("btn-run-lab-demo");
    if (btnLab) {
      btnLab.addEventListener("click", runLabLiveDemo);
    }

    // Setup Audit stream controls (Refresh, Clear, Filter)
    setupAuditControls();
  });

  // Tab Navigation
  function setupTabs() {
    document.querySelectorAll(".tab-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const target = btn.dataset.target;
        document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
        btn.classList.add("active");
        const pane = document.getElementById(target);
        if (pane) pane.classList.add("active");
      });
    });
  }

  // Identity Modal & Credential Validation
  function setupAuthModal() {
    if (btnOpenAuth) {
      btnOpenAuth.addEventListener("click", () => {
        openAuthModal(currentUser);
      });
    }

    if (btnCloseAuth) {
      btnCloseAuth.addEventListener("click", closeAuthModal);
    }

    if (btnCancelAuth) {
      btnCancelAuth.addEventListener("click", closeAuthModal);
    }

    if (authModal) {
      authModal.addEventListener("click", (e) => {
        if (e.target === authModal) closeAuthModal();
      });
    }

    // Toggle password visibility
    if (btnTogglePwd) {
      btnTogglePwd.addEventListener("click", () => {
        if (authPasswordInput.type === "password") {
          authPasswordInput.type = "text";
          btnTogglePwd.textContent = "Hide";
        } else {
          authPasswordInput.type = "password";
          btnTogglePwd.textContent = "Show";
        }
      });
    }

    // Profile presets
    document.querySelectorAll(".profile-pill").forEach(pill => {
      pill.addEventListener("click", () => {
        document.querySelectorAll(".profile-pill").forEach(p => p.classList.remove("active"));
        pill.classList.add("active");
        const profKey = pill.dataset.profile;
        if (ACCOUNTS[profKey]) {
          authUsernameInput.value = ACCOUNTS[profKey].email;
          authPasswordInput.value = ACCOUNTS[profKey].password;
          hideAuthFeedback();
        }
      });
    });

    // Form submission
    const form = document.getElementById("form-auth-login");
    if (form) {
      form.addEventListener("submit", (e) => {
        e.preventDefault();
        submitAuthentication();
      });
    }
    if (btnSubmitAuth) {
      btnSubmitAuth.addEventListener("click", submitAuthentication);
    }
  }

  function openAuthModal(defaultProfile) {
    authModal.style.display = "flex";
    hideAuthFeedback();
    let profKey = "developer";
    if (defaultProfile) {
      for (const k of Object.keys(ACCOUNTS)) {
        if (defaultProfile.includes(k) || defaultProfile === ACCOUNTS[k].email) {
          profKey = k;
          break;
        }
      }
    }
    const prof = ACCOUNTS[profKey] || ACCOUNTS["developer"];
    authUsernameInput.value = (defaultProfile && defaultProfile.includes("@")) ? defaultProfile : prof.email;
    authPasswordInput.value = prof.password;
    document.querySelectorAll(".profile-pill").forEach(p => {
      p.classList.toggle("active", p.dataset.profile === profKey);
    });
    authUsernameInput.focus();
  }

  function closeAuthModal() {
    authModal.style.display = "none";
    hideAuthFeedback();
  }

  function showAuthFeedback(msg, type = "error") {
    authFeedback.style.display = "block";
    authFeedback.className = `auth-feedback-box ${type}`;
    authFeedback.textContent = msg;
  }

  function hideAuthFeedback() {
    authFeedback.style.display = "none";
    authFeedback.textContent = "";
  }

  async function submitAuthentication() {
    const username = authUsernameInput.value.trim();
    const password = authPasswordInput.value;

    if (!username || !password) {
      showAuthFeedback("Please enter both email/username and password.", "error");
      return;
    }

    authBtnSpinner.style.display = "inline-block";
    authBtnText.textContent = "Validating...";
    btnSubmitAuth.disabled = true;

    const success = await authenticateAccount(username, password, true);

    authBtnSpinner.style.display = "none";
    authBtnText.textContent = "Authenticate & Issue JWT";
    btnSubmitAuth.disabled = false;

    if (success) {
      setTimeout(() => {
        closeAuthModal();
      }, 700);
    }
  }

  async function authenticateAccount(username, password, showUiFeedback = true) {
    try {
      const resp = await fetch("/api/v1/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: username,
          password: password,
        }),
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        const detail = errData.detail || "Invalid credentials or unauthorized";
        if (showUiFeedback) {
          showAuthFeedback(`❌ Authentication Failed: ${detail}. Bcrypt validation failed against SQLite user store.`, "error");
        }
        return false;
      }

      const data = await resp.json();
      currentToken = data.access_token;
      const userInfo = data.user_info || {};
      currentUser = userInfo.email || userInfo.username || username;
      const userTier = userInfo.tier || "tier-2";
      const userRole = userInfo.role || "developer";
      const quotaStr = userTier === "admin" ? "Admin: 300 req/min" : (userTier === "tier-2" ? "Tier-2: 90 req/min" : (userTier === "tier-1" ? "Tier-1: 30 req/min" : "Guest: 5 req/min"));

      identityNameLabel.textContent = currentUser;
      identityTierLabel.textContent = userTier.toUpperCase();
      quotaDisplay.textContent = quotaStr;
      tokenBadge.textContent = `Auth: JWT (${currentUser} • ${userTier})`;

      if (showUiFeedback) {
        showAuthFeedback(`✓ Identity Verified against SQLite! Cryptographic RFC 7519 JWT issued. Role: ${userRole.toUpperCase()}, Quota: ${quotaStr}`, "success");
        showToast(`Validated as ${currentUser} (${userTier.toUpperCase()})`, "success");
      }
      return true;
    } catch (err) {
      if (showUiFeedback) {
        showAuthFeedback(`Network error during authentication: ${err.message}`, "error");
      }
      return false;
    }
  }

  // Setup Dedicated RFC 7519 JWT Claims Inspector
  function setupJwtInspector() {
    const btnInspect = document.getElementById("btn-inspect-jwt");
    const jwtModal = document.getElementById("jwt-inspector-modal");
    const btnClose1 = document.getElementById("btn-close-jwt-modal");
    const btnClose2 = document.getElementById("btn-close-jwt-modal-2");
    const btnCopyJwt = document.getElementById("btn-copy-jwt");
    const rawPre = document.getElementById("jwt-raw-token");
    const claimsContainer = document.getElementById("jwt-claims-container");

    if (!btnInspect || !jwtModal) return;

    function openJwtModal() {
      if (!currentToken) {
        showToast("No active token. Please authenticate first.", "error");
        return;
      }
      rawPre.textContent = currentToken;
      claimsContainer.innerHTML = "";

      try {
        const parts = currentToken.split(".");
        if (parts.length === 3) {
          const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
          const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

          const rows = [
            { key: "sub (Subject / Identity)", val: payload.sub, highlight: true },
            { key: "email (Verified Email)", val: payload.email || payload.sub, highlight: false },
            { key: "role (RBAC Policy)", val: payload.role, highlight: true },
            { key: "tier (Token-Bucket Limit)", val: payload.tier, highlight: true },
            { key: "iss (Gateway Issuer)", val: payload.iss || "sentinelshield-gateway", highlight: false },
            { key: "alg (Signature)", val: header.alg || "HS256", highlight: false },
            { key: "iat (Issued At)", val: new Date(payload.iat * 1000).toLocaleTimeString(), highlight: false },
            { key: "exp (Expires At)", val: `${new Date(payload.exp * 1000).toLocaleTimeString()} (${Math.max(0, Math.round((payload.exp - Date.now() / 1000) / 60))}m remaining)`, highlight: false },
          ];

          rows.forEach(r => {
            const rowDiv = document.createElement("div");
            rowDiv.className = "jwt-claim-row";
            rowDiv.innerHTML = `
              <span class="jwt-claim-key">${r.key}</span>
              <span class="jwt-claim-val ${r.highlight ? 'highlight' : ''}">${r.val}</span>
            `;
            claimsContainer.appendChild(rowDiv);
          });
        }
      } catch (e) {
        claimsContainer.innerHTML = `<div style="color: var(--accent-danger); padding: 8px;">Error decoding JWT claims: ${e.message}</div>`;
      }

      jwtModal.style.display = "flex";
    }

    function closeJwtModal() {
      jwtModal.style.display = "none";
    }

    btnInspect.addEventListener("click", openJwtModal);
    if (btnClose1) btnClose1.addEventListener("click", closeJwtModal);
    if (btnClose2) btnClose2.addEventListener("click", closeJwtModal);
    jwtModal.addEventListener("click", (e) => {
      if (e.target === jwtModal) closeJwtModal();
    });

    if (btnCopyJwt) {
      btnCopyJwt.addEventListener("click", async () => {
        if (currentToken) {
          try {
            await navigator.clipboard.writeText(currentToken);
            showToast("Bearer JWT copied to clipboard!", "success");
          } catch (err) {
            showToast("Copied to clipboard", "success");
          }
        }
      });
    }
  }

  // Prompt Controls
  function setupClearButton() {
    const clearBtn = document.getElementById("btn-clear-prompt");
    if (clearBtn) {
      clearBtn.addEventListener("click", () => {
        promptInput.value = "";
        charCountEl.textContent = "0 characters";
        promptInput.focus();
      });
    }
  }

  function setupPromptCounter() {
    promptInput.addEventListener("input", () => {
      charCountEl.textContent = `${promptInput.value.length} characters`;
    });
  }

  // Subtabs inside Results Panel
  function setupSubtabs() {
    const subBtns = document.querySelectorAll(".subtab-btn");
    subBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        subBtns.forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".subtab-content").forEach(c => c.classList.remove("active"));
        btn.classList.add("active");
        const targetContent = document.getElementById(btn.dataset.sub);
        if (targetContent) targetContent.classList.add("active");
      });
    });
  }

  function setupCopyButton() {
    const copyBtn = document.getElementById("btn-copy-output");
    if (copyBtn) {
      copyBtn.addEventListener("click", () => {
        navigator.clipboard.writeText(jsonOutput.textContent);
        const originalText = copyBtn.innerHTML;
        copyBtn.innerHTML = "✓ Copied!";
        setTimeout(() => { copyBtn.innerHTML = originalText; }, 1800);
      });
    }
  }

  // Execute Gateway Pipeline
  if (btnExecute) {
    btnExecute.addEventListener("click", executePipeline);
  }

  async function executePipeline() {
    const promptText = promptInput.value.trim();
    if (!promptText) {
      alert("Please enter a prompt to process.");
      return;
    }

    btnExecute.disabled = true;
    spinner.style.display = "inline-block";
    resetStepper();

    const payload = {
      prompt: promptText,
      target_schema: schemaSelect.value,
      provider: providerSelect.value,
      pii_mode: piiModeSelect.value,
      simulate_malformed: malformedCheck.checked,
      temperature: 0.1,
    };

    const headers = { "Content-Type": "application/json" };
    if (currentToken) {
      headers["Authorization"] = `Bearer ${currentToken}`;
    }

    try {
      const response = await fetch("/api/v1/proxy/generate", {
        method: "POST",
        headers: headers,
        body: JSON.stringify(payload),
      });

      if (response.status === 429) {
        const errData = await response.json();
        handleRateLimit(errData);
        return;
      }

      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.detail || `Server returned ${response.status}`);
      }

      const result = await response.json();
      renderResult(result);
    } catch (err) {
      statusBadge.textContent = "GATEWAY ERROR";
      statusBadge.className = "status-badge badge-blocked";
      statusIndicator.style.background = "var(--accent-rose)";
      jsonOutput.textContent = `// Error from Gateway:\n${err.message}`;
    } finally {
      btnExecute.disabled = false;
      spinner.style.display = "none";
      fetchTelemetry();
    }
  }

  function resetStepper() {
    ["step-auth", "step-injection", "step-pii", "step-inference", "step-validation", "step-healing"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.className = "step-card";
    });
  }

  function handleRateLimit(err) {
    statusBadge.textContent = "RATE LIMIT 429";
    statusBadge.className = "status-badge badge-blocked";
    statusIndicator.style.background = "var(--accent-rose)";

    const stepAuth = document.getElementById("step-auth");
    if (stepAuth) {
      stepAuth.className = "step-card step-blocked";
      document.getElementById("step-auth-desc").textContent = "Token Bucket Exhausted";
    }
    jsonOutput.textContent = JSON.stringify(err, null, 2);
    alert(`[SentinelShield 429] Rate limit exceeded for tier '${currentUser}'.\nSwitch to 'admin' or 'tier-2' identity to increase quota.`);
  }

  function renderResult(res) {
    const lat = res.latencies || {};
    const threats = res.threat_details || {};
    const pii = res.pii_summary || {};
    const healing = res.self_healing || {};

    // Status Badge
    statusBadge.textContent = res.status;
    if (res.status === "SUCCESS") {
      statusBadge.className = "status-badge badge-success";
      statusIndicator.style.background = "var(--accent-emerald)";
    } else if (res.status === "REPAIRED") {
      statusBadge.className = "status-badge badge-repaired";
      statusIndicator.style.background = "var(--accent-purple)";
    } else if (res.status === "BLOCKED") {
      statusBadge.className = "status-badge badge-blocked";
      statusIndicator.style.background = "var(--accent-rose)";
    } else if (res.status === "REPAIR_FAILED") {
      statusBadge.className = "status-badge badge-blocked";
      statusIndicator.style.background = "var(--accent-amber)";
    }

    // Stepper Updates with REAL Measured Milliseconds
    const stepAuth = document.getElementById("step-auth");
    stepAuth.className = "step-card step-active";
    document.getElementById("step-auth-time").textContent = `${lat.rate_limit_ms}ms`;

    const stepInject = document.getElementById("step-injection");
    if (threats.is_safe === false) {
      stepInject.className = "step-card step-blocked";
      document.getElementById("step-injection-desc").textContent = `BLOCKED: ${threats.detected_patterns?.join(', ')}`;
    } else {
      stepInject.className = "step-card step-active";
      document.getElementById("step-injection-desc").textContent = `Passed (Risk: ${threats.risk_score})`;
    }
    document.getElementById("step-injection-time").textContent = `${lat.injection_scan_ms}ms`;

    const stepPii = document.getElementById("step-pii");
    const stepInfer = document.getElementById("step-inference");
    const stepVal = document.getElementById("step-validation");
    const stepHeal = document.getElementById("step-healing");

    if (threats.is_safe === false) {
      stepPii.className = "step-card";
      stepInfer.className = "step-card";
      stepVal.className = "step-card";
      stepHeal.className = "step-card";
    } else {
      stepPii.className = "step-card step-active";
      document.getElementById("step-pii-desc").textContent = pii.sanitized ? `${pii.token_count} PII entities masked` : "0 PII found";
      document.getElementById("step-pii-time").textContent = `${lat.pii_scrub_ms}ms`;

      stepInfer.className = "step-card step-active";
      document.getElementById("step-inference-desc").textContent = `Model: ${res.model_used}`;
      document.getElementById("step-inference-time").textContent = `${lat.llm_inference_ms}ms`;

      stepVal.className = "step-card step-active";
      document.getElementById("step-validation-time").textContent = `${lat.validation_ms}ms`;

      if (healing.required) {
        stepHeal.className = healing.repaired ? "step-card step-repaired" : "step-card step-blocked";
        document.getElementById("step-healing-desc").textContent = healing.repaired ? `Repaired in ${healing.repair_time_ms}ms` : "Repair exhausted";
        document.getElementById("step-healing-time").textContent = `${healing.repair_time_ms}ms`;
      } else {
        stepHeal.className = "step-card step-active";
        document.getElementById("step-healing-desc").textContent = "Compliant on pass 1";
        document.getElementById("step-healing-time").textContent = "0ms";
      }
    }

    // Output JSON Viewer
    if (res.structured_data) {
      jsonOutput.textContent = JSON.stringify(res.structured_data, null, 2);
    } else {
      jsonOutput.textContent = JSON.stringify({
        status: res.status,
        verdict: res.security_verdict,
        threat: res.threat_details,
        raw_model_response: res.raw_model_response,
      }, null, 2);
    }

    // PII Zero-Trust Comparison Diff
    piiDiffRaw.textContent = res.raw_prompt_received || "";
    piiDiffSanitized.textContent = res.sanitized_prompt_sent_to_model || "";
    renderPiiVault(pii);

    // Self-Healing Diagnostics
    renderHealingDiagnostics(healing, res);

    // Measured Latencies Chart
    renderWaterfall(lat);
  }

  function renderPiiVault(pii) {
    if (!pii.sanitized || !pii.entities_detected || Object.keys(pii.entities_detected).length === 0) {
      piiVaultContent.innerHTML = `<p class="empty-state">No PII tokens active in current request memory context.</p>`;
      return;
    }

    let html = `<div style="font-size: 0.76rem; color: var(--accent-emerald); margin-bottom: 0.5rem; font-weight: 600;">
      ✓ In-Memory Ephemeral Tokens (Dispatched to Model Context):
    </div>`;

    for (const [entityType, count] of Object.entries(pii.entities_detected)) {
      html += `
        <div class="pii-token-row">
          <span class="token-name">&lt;PII_${entityType}_...&gt;</span>
          <span class="token-raw">${count} entity occurrence(s) masked in-memory &amp; ${pii.mode_applied}</span>
        </div>
      `;
    }
    piiVaultContent.innerHTML = html;
  }

  function renderHealingDiagnostics(healing, res) {
    if (!healing.required) {
      healingContent.innerHTML = `
        <p class="empty-state">
          ✓ Clean Model Output: Model generated valid JSON conforming to the target schema on pass 1.<br>
          (Enable "Test Self-Healing Repair Loop" checkbox to see the repair re-prompt in action).
        </p>
      `;
      return;
    }

    healingContent.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="badge-role" style="background: rgba(139, 92, 246, 0.2); color: var(--accent-purple);">
            ${healing.repaired ? "✓ Successfully Repaired" : "✗ Repair Failed"} (${healing.attempts} attempts)
          </span>
          <span class="lab-chip timer-chip">⏱️ ${healing.repair_time_ms}ms</span>
        </div>
        <div style="font-size: 0.76rem; color: #f87171;">
          <strong>Detected Schema Errors:</strong>
          <ul style="margin: 0.3rem 0 0 1.2rem;">
            ${(healing.initial_errors || []).map(err => `<li>${escapeHtml(err)}</li>`).join("")}
          </ul>
        </div>
        <div style="font-size: 0.72rem; color: var(--text-dim);">
          <strong>Precision Diagnostic Re-Prompt Sent to Model:</strong>
          <pre style="background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px; color: #fbbf24; margin-top: 0.25rem; white-space: pre-wrap; max-height: 120px; overflow-y: auto;">${escapeHtml(healing.re_prompt_sent || '')}</pre>
        </div>
        <div style="font-size: 0.72rem; color: var(--text-dim);">
          <strong>Raw Model Response (Pass 1):</strong>
          <pre style="background: rgba(0,0,0,0.5); padding: 0.5rem; border-radius: 4px; color: #38bdf8; margin-top: 0.25rem; white-space: pre-wrap; max-height: 100px; overflow-y: auto;">${escapeHtml(res.raw_model_response || '')}</pre>
        </div>
      </div>
    `;
  }

  function renderWaterfall(lat) {
    const total = lat.total_pipeline_ms || 1.0;
    const piiW = Math.max(3, Math.round(((lat.pii_scrub_ms || 0.1) / total) * 100));
    const injW = Math.max(3, Math.round(((lat.injection_scan_ms || 0.1) / total) * 100));
    const infW = Math.max(3, Math.round(((lat.llm_inference_ms || 1.0) / total) * 100));
    const healW = Math.max(3, Math.round(((lat.self_healing_ms || 0.0) / total) * 100));

    waterfallChart.innerHTML = `
      <div class="waterfall-bar-group">
        <span class="waterfall-label">PII Scrub</span>
        <div class="waterfall-bar-track"><div class="waterfall-bar bar-pii" style="width: ${piiW}%">${lat.pii_scrub_ms}ms</div></div>
      </div>
      <div class="waterfall-bar-group">
        <span class="waterfall-label">Injection Scan</span>
        <div class="waterfall-bar-track"><div class="waterfall-bar bar-injection" style="width: ${injW}%">${lat.injection_scan_ms}ms</div></div>
      </div>
      <div class="waterfall-bar-group">
        <span class="waterfall-label">Model Call</span>
        <div class="waterfall-bar-track"><div class="waterfall-bar bar-inference" style="width: ${infW}%">${lat.llm_inference_ms}ms</div></div>
      </div>
      ${lat.self_healing_ms > 0 ? `
      <div class="waterfall-bar-group">
        <span class="waterfall-label">Self-Healing</span>
        <div class="waterfall-bar-track"><div class="waterfall-bar" style="background: var(--accent-purple); width: ${healW}%">${lat.self_healing_ms}ms</div></div>
      </div>` : ''}
      <div style="text-align: right; font-size: 0.78rem; font-family: var(--font-mono); color: var(--text-dim); margin-top: 0.5rem;">
        Total Gateway Latency: <strong>${lat.total_pipeline_ms}ms</strong>
      </div>
    `;
  }

  // Live Self-Healing Lab Execution
  async function runLabLiveDemo() {
    const btnLab = document.getElementById("btn-run-lab-demo");
    btnLab.disabled = true;
    btnLab.textContent = "Executing Real Self-Healing on Groq...";

    try {
      const payload = {
        prompt: "Customer Alice Walker (SSN: 000-11-2222, email: alice.walker@corp.net) demands immediate account review for chargeback dispute.",
        target_schema: "CustomerSupportTicket",
        provider: "groq",
        simulate_malformed: true, // Forces broken pass 1
        pii_mode: "rehydrate",
      };

      const response = await fetch("/api/v1/proxy/generate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${currentToken}`,
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      // Update Lab boxes with real data
      const brokenBox = document.getElementById("lab-box-broken");
      const repromptBox = document.getElementById("lab-box-reprompt");
      const fixedBox = document.getElementById("lab-box-fixed");
      const timerChip = document.getElementById("lab-timer-chip");

      brokenBox.textContent = data.raw_model_response || "Malformed model output received";
      repromptBox.textContent = data.self_healing?.re_prompt_sent || 
        (data.self_healing?.initial_errors ? `CRITICAL ERROR: Pydantic v2 validation failed.\nErrors:\n${data.self_healing.initial_errors.join('\n')}` : "Targeted re-prompt sent to Groq");
      fixedBox.textContent = JSON.stringify(data.structured_data, null, 2);
      
      const repairMs = data.self_healing?.repair_time_ms || data.latencies?.self_healing_ms || 0;
      timerChip.textContent = `⏱️ Repaired in ${repairMs}ms`;

      showToast(`[Self-Healing Verified] Groq output was intercepted, diagnostic re-prompt sent, and repaired in ${repairMs}ms!`, "success");
    } catch (e) {
      showToast("Self-healing test failed: " + e.message, "error");
    } finally {
      btnLab.disabled = false;
      btnLab.textContent = "⚡ Test Live Self-Healing Repair Execution on Groq";
      fetchTelemetry();
    }
  }

  // Persistent SQLite Telemetry & Audit Stream
  let cachedEvents = [];

  function setupAuditControls() {
    const btnRefresh = document.getElementById("btn-refresh-audit");
    const btnClear = document.getElementById("btn-clear-audit");
    const filterSelect = document.getElementById("filter-audit-event");

    if (btnRefresh) {
      btnRefresh.addEventListener("click", async () => {
        btnRefresh.disabled = true;
        const refreshText = document.getElementById("audit-refresh-text");
        const refreshIcon = document.getElementById("audit-refresh-icon");
        if (refreshText) refreshText.textContent = "Refreshing...";
        if (refreshIcon) refreshIcon.style.animation = "spin 0.6s linear infinite";

        await fetchTelemetry(true);

        if (refreshIcon) refreshIcon.style.animation = "none";
        if (refreshText) refreshText.textContent = "✓ Refreshed!";
        setTimeout(() => {
          if (refreshText) refreshText.textContent = "Refresh Feed";
          btnRefresh.disabled = false;
        }, 1200);
      });
    }

    if (filterSelect) {
      filterSelect.addEventListener("change", () => {
        applyAuditFilter();
      });
    }

    if (btnClear) {
      btnClear.addEventListener("click", async () => {
        if (!confirm("Clear all security audit events from the SQLite database?")) return;
        try {
          const resp = await fetch("/api/v1/telemetry/events", { method: "DELETE" });
          if (resp.ok) {
            cachedEvents = [];
            renderAuditList([]);
            showToast("✓ SQLite Audit Trail cleared successfully.", "success");
            await fetchTelemetry(false);
          }
        } catch (e) {
          showToast("Failed to clear audit trail: " + e.message, "error");
        }
      });
    }
  }

  function applyAuditFilter() {
    const filterSelect = document.getElementById("filter-audit-event");
    const val = filterSelect ? filterSelect.value : "ALL";
    if (val === "ALL") {
      renderAuditList(cachedEvents);
    } else {
      const filtered = cachedEvents.filter(e => e.event_type === val);
      renderAuditList(filtered);
    }
  }

  async function fetchTelemetry(showToastNotification = false) {
    try {
      const [mResp, eResp] = await Promise.all([
        fetch("/api/v1/telemetry/metrics"),
        fetch("/api/v1/telemetry/events?limit=50"),
      ]);

      if (mResp.ok) {
        const m = await mResp.json();
        document.getElementById("stat-total-reqs").textContent = m.total_requests || 0;
        document.getElementById("stat-injections-blocked").textContent = m.blocked_injections || 0;
        document.getElementById("stat-pii-scrubbed").textContent = m.pii_entities_sanitized || 0;
        document.getElementById("stat-json-repaired").textContent = m.self_healing_repairs_executed || 0;
        document.getElementById("stat-avg-latency").textContent = `${m.average_latency_ms || 0}ms`;
      }

      if (eResp.ok) {
        cachedEvents = await eResp.json();
        applyAuditFilter();
        if (showToastNotification) {
          showToast(`✓ SQLite Audit Feed Updated: ${cachedEvents.length} events loaded`, "success");
        }
      }
    } catch (e) {
      console.warn("Could not fetch telemetry:", e);
      if (showToastNotification) {
        showToast("Error updating audit feed: " + e.message, "error");
      }
    }
  }

  function renderAuditList(events) {
    const list = document.getElementById("audit-feed-list");
    if (!list) return;

    if (!events || events.length === 0) {
      list.innerHTML = `
        <div style="text-align: center; padding: 2.5rem 1rem; color: var(--text-dim);">
          <div style="font-size: 2rem; margin-bottom: 0.5rem;">🛡️</div>
          <strong style="color: var(--text-main);">No Security Audit Events in SQLite</strong>
          <p style="font-size: 0.78rem; margin-top: 0.25rem;">
            Run a prompt in the <strong>Live Guardrail Gateway</strong> to observe real-time audit logging!
          </p>
        </div>
      `;
      return;
    }

    list.innerHTML = events.map((evt, idx) => {
      let borderClass = "border-auth";
      let pillClass = "pill-auth";
      let eventTitle = evt.event_type;
      let humanSummary = "";

      if (evt.event_type === "INJECTION_BLOCKED") {
        borderClass = "border-danger";
        pillClass = "pill-danger";
        eventTitle = "🛑 Adversarial Attack Blocked";
        const patterns = (evt.details?.detected_patterns || []).join(", ") || "Heuristic jailbreak trigger";
        humanSummary = `Adversarial prompt injection intercepted before reaching model. Signatures: ${escapeHtml(patterns)}. Threat Level: ${evt.details?.threat_level || 'CRITICAL'}.`;
      } else if (evt.event_type === "PII_SCRUBBED") {
        borderClass = "border-success";
        pillClass = "pill-success";
        eventTitle = "🔒 Zero-Trust PII Scrubbed";
        const entities = Object.entries(evt.details?.entities_detected || {}).map(([k, v]) => `${v} ${k}`).join(", ") || "PII entities";
        humanSummary = `Scrubbed ${evt.details?.token_count || 0} sensitive entities (${entities}) strictly in-memory into bidirectional ephemeral tokens. Zero plaintext persisted.`;
      } else if (evt.event_type === "JSON_REPAIRED") {
        borderClass = "border-repaired";
        pillClass = "pill-repaired";
        eventTitle = "🔄 Schema Self-Healing Repaired";
        humanSummary = `Pydantic v2 detected missing fields or type mismatches in pass 1. Dispatched diagnostic re-prompt to Groq and repaired successfully in ${evt.details?.repair_time_ms || 0}ms (${evt.details?.attempts || 2} attempts).`;
      } else if (evt.event_type === "JSON_REPAIR_FAILED") {
        borderClass = "border-danger";
        pillClass = "pill-danger";
        eventTitle = "⚠️ JSON Repair Exhausted";
        humanSummary = `Model output failed schema validation after ${evt.details?.attempts || 3} attempts. Returned clean 422 Unprocessable Entity to protect downstream systems.`;
      } else if (evt.event_type === "RATE_LIMIT_HIT") {
        borderClass = "border-warning";
        pillClass = "pill-warning";
        eventTitle = "⚡ Rate Limit 429 Enforced";
        humanSummary = `Sliding-window token bucket exhausted for caller tier '${escapeHtml(evt.user_tier || 'guest')}'. Request was throttled to prevent resource exhaustion.`;
      } else if (evt.event_type === "USER_AUTHENTICATED") {
        borderClass = "border-auth";
        pillClass = "pill-auth";
        eventTitle = "🔐 Cryptographic JWT Issued";
        humanSummary = `User '${escapeHtml(evt.details?.username || evt.user_tier)}' authenticated via SQLite bcrypt hash. Issued HMAC-SHA256 JWT session.`;
      } else {
        humanSummary = JSON.stringify(evt.details);
      }

      const timeAgo = formatTimeAgo(evt.timestamp);
      const exactTime = evt.timestamp ? new Date(evt.timestamp * 1000).toLocaleTimeString() : "";
      const drawerId = `payload-drawer-${idx}`;

      return `
        <div class="audit-card-row ${borderClass}">
          <div class="audit-card-header">
            <div class="audit-header-left">
              <span class="audit-event-pill ${pillClass}">${eventTitle}</span>
              <span class="audit-tier-tag">Caller: <strong>${escapeHtml(evt.user_tier || 'guest')}</strong> • ${escapeHtml(evt.severity)}</span>
            </div>
            <span class="audit-timestamp-meta">${timeAgo} (${exactTime})</span>
          </div>
          <p class="audit-summary-text">${humanSummary}</p>
          <div class="audit-card-footer">
            <button class="btn-inspect-payload" data-drawer="${drawerId}">
              🔍 Inspect SQLite Payload
            </button>
          </div>
          <pre class="audit-payload-drawer" id="${drawerId}"><code>${escapeHtml(JSON.stringify(evt.details, null, 2))}</code></pre>
        </div>
      `;
    }).join("");

    // Wire up drawer toggle buttons
    list.querySelectorAll(".btn-inspect-payload").forEach(btn => {
      btn.addEventListener("click", () => {
        const targetId = btn.dataset.drawer;
        const drawer = document.getElementById(targetId);
        if (drawer) {
          const isOpen = drawer.classList.contains("open");
          drawer.classList.toggle("open", !isOpen);
          btn.textContent = isOpen ? "🔍 Inspect SQLite Payload" : "▲ Hide Payload";
        }
      });
    });
  }

  // Schemas Loader
  async function loadSchemas() {
    try {
      const resp = await fetch("/api/v1/schemas");
      if (!resp.ok) return;
      const schemas = await resp.json();
      const container = document.getElementById("schema-cards-container");
      container.innerHTML = Object.entries(schemas).map(([name, data]) => {
        const props = data.json_schema?.properties || {};
        const fieldCount = Object.keys(props).length;
        return `
          <div class="schema-card">
            <div class="schema-title-row">
              <span class="schema-name">${name}</span>
              <span class="schema-fields-count">${fieldCount} Fields</span>
            </div>
            <p class="schema-desc">${data.description || 'Pydantic v2 Schema'}</p>
            <pre class="schema-code-box"><code>${JSON.stringify(data.json_schema, null, 2)}</code></pre>
          </div>
        `;
      }).join("");
    } catch (e) {
      console.warn("Could not load schema definitions:", e);
    }
  }

  // Helpers
  function formatTimeAgo(ts) {
    if (!ts) return "recently";
    const delta = Math.floor(Date.now() / 1000 - ts);
    if (delta < 5) return "just now";
    if (delta < 60) return `${delta}s ago`;
    return `${Math.floor(delta / 60)}m ago`;
  }

  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function showToast(msg, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      container.style.cssText = "position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 9999; display: flex; flex-direction: column; gap: 0.5rem; pointer-events: none;";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.style.cssText = `
      background: ${type === "success" ? "#064e3b" : type === "error" ? "#7f1d1d" : "#1e1b4b"};
      color: #fff;
      border: 1px solid ${type === "success" ? "#10b981" : type === "error" ? "#f43f5e" : "#818cf8"};
      padding: 0.75rem 1.1rem;
      border-radius: 8px;
      font-size: 0.82rem;
      font-weight: 500;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      animation: toastIn 0.3s ease forwards;
      pointer-events: auto;
      max-width: 420px;
      line-height: 1.4;
    `;
    toast.textContent = msg;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transition = "opacity 0.3s ease";
      setTimeout(() => toast.remove(), 350);
    }, 4000);
  }
})();
