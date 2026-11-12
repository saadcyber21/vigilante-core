"use strict";

const minutesAgo = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();
const demoAlerts = [
  { id: "VIG-2048", source_key: "identity-provider", ai_severity: "critical", status: "new", received_at: minutesAgo(4), ai_confidence: 0.96, ai_summary: "Privileged account sign-in followed by MFA fatigue attempts", payload: { event_type: "authentication", user: "j.smith@example.test", source_ip: "198.51.100.42", failed_mfa_prompts: 9, test: true }, case_id: null },
  { id: "VIG-2047", source_key: "endpoint-edr", ai_severity: "high", status: "investigating", received_at: minutesAgo(18), ai_confidence: 0.88, ai_summary: "Unusual PowerShell child process from a document reader", payload: { event_type: "process_anomaly", host: "WS-FIN-042", process: "powershell.exe", parent: "winword.exe", test: true }, case_id: "CASE-018" },
  { id: "VIG-2046", source_key: "cloud-audit", ai_severity: "high", status: "triaged", received_at: minutesAgo(43), ai_confidence: 0.91, ai_summary: "New access key created outside the approved change window", payload: { event_type: "iam_change", actor: "svc-deploy", region: "us-east-1", test: true }, case_id: null },
  { id: "VIG-2045", source_key: "email-security", ai_severity: "medium", status: "triaged", received_at: minutesAgo(76), ai_confidence: 0.82, ai_summary: "Multiple recipients reported a suspicious invoice attachment", payload: { event_type: "user_report", message_id: "demo-msg-1042", attachment: "invoice-review.html", test: true }, case_id: null },
  { id: "VIG-2044", source_key: "network-sensor", ai_severity: "medium", status: "contained", received_at: minutesAgo(128), ai_confidence: 0.78, ai_summary: "Repeated DNS requests to a newly observed domain", payload: { event_type: "dns_anomaly", host: "ENG-LT-018", domain: "updates-example.test", test: true }, case_id: "CASE-017" },
  { id: "VIG-2043", source_key: "identity-provider", ai_severity: "low", status: "closed", received_at: minutesAgo(213), ai_confidence: 0.69, ai_summary: "Impossible-travel rule matched a known test account", payload: { event_type: "authentication", user: "qa-automation@example.test", test: true }, case_id: null },
  { id: "VIG-2042", source_key: "cloud-audit", ai_severity: "low", status: "triaged", received_at: minutesAgo(301), ai_confidence: 0.73, ai_summary: "Storage policy changed and reverted by an authorized operator", payload: { event_type: "configuration_change", actor: "platform-admin", test: true }, case_id: null },
  { id: "VIG-2041", source_key: "endpoint-edr", ai_severity: "high", status: "investigating", received_at: minutesAgo(412), ai_confidence: 0.89, ai_summary: "Unsigned binary executed from a temporary directory", payload: { event_type: "process_anomaly", host: "ENG-LT-007", image: "sync-helper.exe", test: true }, case_id: "CASE-016" },
  { id: "VIG-2040", source_key: "email-security", ai_severity: "low", status: "closed", received_at: minutesAgo(605), ai_confidence: 0.67, ai_summary: "Bulk-mail alert matched a scheduled internal notification", payload: { event_type: "mail_volume", sender: "no-reply@example.test", test: true }, case_id: null }
];
const demoCases = [
  { id: "CASE-018", case_number: 18, title: "Suspicious endpoint process chain", description: "Review process ancestry and endpoint timeline.", priority: "high", status: "in_progress", alert_ids: ["VIG-2047"], updated_at: minutesAgo(12) },
  { id: "CASE-017", case_number: 17, title: "Unusual DNS activity on engineering host", description: "Validate domain reputation and host activity.", priority: "medium", status: "in_progress", alert_ids: ["VIG-2044"], updated_at: minutesAgo(54) },
  { id: "CASE-016", case_number: 16, title: "Unsigned binary execution", description: "Investigate binary provenance and related events.", priority: "high", status: "open", alert_ids: ["VIG-2041"], updated_at: minutesAgo(189) },
  { id: "CASE-015", case_number: 15, title: "MFA fatigue simulation", description: "Closed synthetic training scenario.", priority: "low", status: "closed", alert_ids: [], updated_at: minutesAgo(840) }
];

const state = {
  mode: "demo",
  alerts: demoAlerts.map((alert) => ({ ...alert })),
  cases: demoCases.map((item) => ({ ...item })),
  proposals: [],
  currentUser: null,
  summary: null,
  apiBase: "",
  token: "",
  selectedAlert: null,
  reviewingProposalId: null,
  severity: "all",
  status: "all",
  search: ""
};
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
const label = (value) => String(value || "unknown").replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
const severityLevels = ["critical", "high", "medium", "low"];

function relativeTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const minutes = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60_000));
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
function formatCount(value) { return new Intl.NumberFormat().format(Number(value) || 0); }
function currentCounts() {
  const counts = Object.fromEntries(severityLevels.map((level) => [level, 0]));
  state.alerts.forEach((alert) => { if (counts[alert.ai_severity] !== undefined) counts[alert.ai_severity] += 1; });
  return counts;
}
function openCases() {
  return state.cases.filter((item) => ["open", "in_progress", "investigating"].includes(String(item.status).toLowerCase())).length;
}
function renderMetrics() {
  const counts = currentCounts();
  const total = state.mode === "live" && state.summary ? Number(state.summary.alerts_total) : state.alerts.length;
  const high = counts.high + counts.critical;
  const open = state.mode === "live" && state.summary ? Number(state.summary.open_cases) : openCases();
  $("#metricAlerts").textContent = formatCount(total);
  $("#metricHigh").textContent = formatCount(high);
  $("#metricCases").textContent = formatCount(open);
  $("#metricCritical").textContent = formatCount(counts.critical);
  $("#navAlertCount").textContent = formatCount(total);
  $("#navCaseCount").textContent = formatCount(state.mode === "live" && state.summary ? state.summary.cases_total : state.cases.length);
  $("#criticalSubtext").textContent = counts.critical ? "Requires prompt review" : "No critical events in this queue";
  $("#metricAlertsNote").textContent = state.mode === "demo" ? "Synthetic records" : "Reported by connected API";
  const totalLoaded = state.alerts.length;
  $("#severityTotal").textContent = `${formatCount(totalLoaded)} loaded`;
  $("#severityBreakdown").innerHTML = severityLevels.map((level) => {
    const count = counts[level];
    const pct = totalLoaded ? Math.round((count / totalLoaded) * 100) : 0;
    return `<div class="severity-row"><span class="severity-row-label"><i class="severity-dot ${level}-dot"></i>${label(level)}</span><span class="severity-bar"><span class="severity-fill ${level}" style="width:${pct}%"></span></span><span class="severity-row-value">${count}</span></div>`;
  }).join("");
}
function renderTrend() {
  const points = [79, 66, 74, 55, 62, 39, 51, 44, 58, 29, 46, 34, 40, 21, 37, 25, 31, 13, 28, 17, 22, 8, 20, 12];
  const width = 650, height = 145, padX = 2, padY = 10;
  const coords = points.map((value, index) => `${padX + index * (width - padX * 2) / (points.length - 1)},${padY + value * (height - padY * 2) / 100}`);
  const line = `M ${coords.join(" L ")}`;
  const area = `${line} L ${width - padX},${height} L ${padX},${height} Z`;
  $("#trendChart").innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Synthetic alert volume over 24 hours"><defs><linearGradient id="areaFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#54d6d2" stop-opacity=".2"/><stop offset="100%" stop-color="#54d6d2" stop-opacity="0"/></linearGradient></defs><path class="chart-grid-line" d="M0 35H${width} M0 75H${width} M0 115H${width}"/><path class="chart-area" d="${area}"/><path class="chart-line" d="${line}"/></svg>`;
  const synthetic = state.mode === "demo";
  $("#trendBadge").textContent = synthetic ? "SYNTHETIC" : "NOT AVAILABLE";
  $("#chartFootnote").textContent = synthetic ? "Sample trend only — historical aggregation is not provided by the demo." : "The connected API does not expose historical trend data; this chart remains illustrative.";
}
function filteredAlerts() {
  const term = state.search.trim().toLowerCase();
  return state.alerts.filter((alert) => {
    const severityMatch = state.severity === "all" || String(alert.ai_severity).toLowerCase() === state.severity;
    const statusMatch = state.status === "all" || String(alert.status).toLowerCase() === state.status;
    const haystack = [alert.id, alert.ai_summary, alert.source_key, alert.payload && JSON.stringify(alert.payload)].join(" ").toLowerCase();
    return severityMatch && statusMatch && (!term || haystack.includes(term));
  });
}
function alertRow(alert) {
  const severity = String(alert.ai_severity || "low").toLowerCase();
  const status = String(alert.status || "triaged").toLowerCase();
  const host = alert.payload && (alert.payload.host || alert.payload.source_ip || alert.payload.user) || "Security event";
  const id = escapeHtml(alert.id);
  return `<tr><td><div class="alert-title"><span class="alert-glyph">⌁</span><span class="alert-title-copy"><strong>${escapeHtml(alert.ai_summary || "Security event")}</strong><small>${id} · ${escapeHtml(host)}</small></span></div></td><td>${escapeHtml(label(alert.source_key))}</td><td><span class="severity-tag ${escapeHtml(severity)}">${escapeHtml(label(severity))}</span></td><td><span class="status-tag ${escapeHtml(status)}">${escapeHtml(label(status))}</span></td><td>${escapeHtml(relativeTime(alert.received_at))}</td><td><button class="row-action" data-alert-id="${id}" aria-label="View details for ${id}">Details</button></td></tr>`;
}
function renderAlertTables() {
  const filtered = filteredAlerts();
  const recent = [...state.alerts].sort((a, b) => new Date(b.received_at || 0) - new Date(a.received_at || 0)).slice(0, 5);
  $("#overviewAlertsBody").innerHTML = recent.map(alertRow).join("");
  $("#alertsBody").innerHTML = filtered.map(alertRow).join("");
  $("#overviewEmpty").hidden = recent.length > 0;
  $("#alertsEmpty").hidden = filtered.length > 0;
  $("#alertResultCount").textContent = `${filtered.length} ${filtered.length === 1 ? "alert" : "alerts"}`;
  $("#alertFootnote").textContent = state.mode === "demo" ? "Demo records are illustrative and not connected to an SIEM." : `Showing ${filtered.length} of ${state.alerts.length} alert records returned by the API.`;
  $("#caseFootnote").textContent = state.mode === "demo" ? "Demo case changes stay in this browser." : "Case changes are sent to the connected Vigilante API.";
}
function caseRow(item) {
  const priority = String(item.priority || "medium").toLowerCase();
  const status = String(item.status || "open").toLowerCase();
  const caseName = item.case_number ? `CASE-${String(item.case_number).padStart(3, "0")}` : String(item.id || "Case").slice(0, 12);
  const statuses = ["open", "in_progress", "contained", "resolved", "closed"];
  const statusControl = `<select class="case-status-select" data-case-id="${escapeHtml(item.id)}" aria-label="Update status for ${escapeHtml(caseName)}">${statuses.map((value) => `<option value="${value}"${value === status ? " selected" : ""}>${escapeHtml(label(value))}</option>`).join("")}</select>`;
  return `<tr><td><span class="case-number">${escapeHtml(caseName)}</span></td><td><div class="case-title-cell"><strong>${escapeHtml(item.title || "Untitled investigation")}</strong><small>${escapeHtml(item.description || "No description")}</small></div></td><td><span class="priority-tag ${escapeHtml(priority)}">${escapeHtml(label(priority))}</span></td><td>${statusControl}</td><td>${formatCount((item.alert_ids || []).length)}</td><td>${escapeHtml(relativeTime(item.updated_at || item.created_at))}</td></tr>`;
}
function renderCases() {
  const cases = [...state.cases].sort((a, b) => new Date(b.updated_at || b.created_at || 0) - new Date(a.updated_at || a.created_at || 0));
  $("#casesBody").innerHTML = cases.map(caseRow).join("");
  $("#casesEmpty").hidden = cases.length > 0;
  $("#caseResultCount").textContent = `${cases.length} ${cases.length === 1 ? "case" : "cases"}`;
}
function renderProposals() {
  const proposals = [...state.proposals].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  const canReview = state.currentUser && ["admin", "manager", "security_admin"].includes(state.currentUser.role);
  $("#navProposalCount").textContent = formatCount(proposals.filter((item) => item.status === "pending").length);
  $("#proposalResultCount").textContent = `${proposals.length} ${proposals.length === 1 ? "proposal" : "proposals"}`;
  $("#responseProposalsBody").innerHTML = proposals.map((item) => {
    const mayReview = item.status === "pending" && canReview && item.proposed_by !== state.currentUser.id;
    const actions = mayReview ? `<button class="row-action" data-review-id="${escapeHtml(item.id)}" data-review-decision="approve">Approve</button> <button class="row-action" data-review-id="${escapeHtml(item.id)}" data-review-decision="reject">Reject</button>` : "—";
    return `<tr><td>${escapeHtml(label(item.action_type))}</td><td>${escapeHtml(String(item.alert_id || "").slice(0, 12))}</td><td>${escapeHtml(item.target_reference || "—")}</td><td class="proposal-rationale">${escapeHtml(item.rationale || "—")}</td><td><span class="status-tag ${escapeHtml(item.status || "pending")}">${escapeHtml(label(item.status))}</span></td><td>${escapeHtml(item.review_reason || (item.status === "pending" ? "Awaiting a different reviewer" : "Reviewed"))}</td><td>${actions}</td></tr>`;
  }).join("");
  $("#proposalsEmpty").hidden = proposals.length > 0;
  $("#proposalFootnote").textContent = state.mode === "demo"
    ? "Synthetic demo data does not create approvals. Connect a live API to use this workflow."
    : "Approval records a decision only. Vigilante does not execute commands or call response integrations.";
}
function renderMode() {
  const live = state.mode === "live";
  $("#modePill").classList.toggle("live", live);
  $("#modeLabel").textContent = live ? "LIVE API" : "DEMO MODE";
  $("#sidebarMode").textContent = live ? "Connected API" : "Demo environment";
  $("#demoBanner").hidden = live || sessionStorage.getItem("vigilante-banner-dismissed") === "1";
  $("#liveNotice").hidden = !live;
  $("#connectButton").textContent = live ? "Disconnect API" : "Connect API";
}
function renderAll() {
  renderMode();
  renderMetrics();
  renderTrend();
  renderAlertTables();
  renderCases();
  renderProposals();
}
function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  window.clearTimeout(toast.timer);
  toast.timer = window.setTimeout(() => element.classList.remove("show"), 3000);
}
function showView(name) {
  const known = ["overview", "alerts", "cases", "approvals", "integrations"];
  const view = known.includes(name) ? name : "overview";
  $$('[data-view-panel]').forEach((panel) => { panel.hidden = panel.dataset.viewPanel !== view; });
  $$(".nav-item[data-view]").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $("#currentPageName").textContent = ({ overview: "Overview", alerts: "Alert queue", cases: "Cases", approvals: "Response approvals", integrations: "Integrations" })[view];
  $("#sidebar").classList.remove("open");
  $("#mobileMenu").setAttribute("aria-expanded", "false");
}
function openDrawer(alertId) {
  const alert = state.alerts.find((item) => String(item.id) === String(alertId));
  if (!alert) return;
  state.selectedAlert = alert;
  const severity = String(alert.ai_severity || "low").toLowerCase();
  const status = String(alert.status || "triaged").toLowerCase();
  $("#drawerTitle").textContent = alert.id || "Alert";
  $("#drawerContent").innerHTML = `<div class="drawer-section"><p class="drawer-label">ASSESSMENT</p><div style="display:flex;gap:7px;margin-bottom:10px"><span class="severity-tag ${escapeHtml(severity)}">${escapeHtml(label(severity))}</span><span class="status-tag ${escapeHtml(status)}">${escapeHtml(label(status))}</span></div><div class="drawer-summary">${escapeHtml(alert.ai_summary || "No summary available.")}</div></div><div class="drawer-section drawer-meta"><div><span>Source</span><strong>${escapeHtml(label(alert.source_key))}</strong></div><div><span>Received</span><strong>${escapeHtml(new Date(alert.received_at || Date.now()).toLocaleString())}</strong></div><div><span>Baseline confidence</span><strong>${alert.ai_confidence == null ? "Not supplied" : `${Math.round(Number(alert.ai_confidence) * 100)}%`}</strong></div><div><span>Case</span><strong>${escapeHtml(alert.case_id || "Not linked")}</strong></div></div><div class="drawer-section"><p class="drawer-label">AI INVESTIGATION BRIEF</p><p class="form-note">On-demand, evidence-grounded analyst assistance. In live mode, this alert is sent to the AI provider configured by the API operator. Suggestions are advisory; no action is executed.</p><button class="button button-primary button-small" id="investigateAlertButton">${state.mode === "demo" ? "Preview sample brief" : "Generate investigation brief"}</button><div id="investigationResult" aria-live="polite"></div></div><div class="drawer-section"><p class="drawer-label">EVENT PAYLOAD</p><pre class="payload-box">${escapeHtml(JSON.stringify(alert.payload || {}, null, 2))}</pre></div><div class="drawer-actions"><button class="button button-primary button-small" id="createCaseButton">Create case</button><button class="button button-quiet button-small" id="proposeResponseButton">Propose response</button><button class="button button-quiet button-small" id="closeDetailsButton">Close</button></div>`;
  $("#drawerBackdrop").hidden = false;
  $("#detailDrawer").classList.add("open");
  $("#detailDrawer").setAttribute("aria-hidden", "false");
  $("#drawerContent").insertAdjacentHTML("beforeend", `<div class="drawer-section"><p class="drawer-label">TRIAGE STATUS</p><label class="drawer-field-label" for="alertStatusSelect">Status</label><select id="alertStatusSelect"><option value="new">New</option><option value="triaged">Triaged</option><option value="investigating">Investigating</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select><label class="drawer-field-label" for="alertStatusReason">Reason for change</label><input id="alertStatusReason" type="text" maxlength="2000" placeholder="Document the analyst decision"><button class="button button-quiet button-small drawer-status-save" id="saveAlertStatus">Save status</button></div>`);
  $("#alertStatusSelect").value = ["new", "triaged", "investigating", "contained", "resolved", "closed"].includes(status) ? status : "triaged";
  $("#saveAlertStatus").addEventListener("click", () => updateSelectedAlertStatus());
  $("#investigateAlertButton").addEventListener("click", () => generateInvestigationBrief(alert));
  $("#createCaseButton").addEventListener("click", () => createCaseFromSelected());
  $("#proposeResponseButton").addEventListener("click", () => openProposalModal(alert.id));
  $("#closeDetailsButton").addEventListener("click", closeDrawer);
}
function renderInvestigationBrief(brief, notice, investigationId = null) {
  const result = $("#investigationResult");
  if (!result) return;
  result.innerHTML = `<div class="drawer-summary investigation-assessment">${escapeHtml(brief.assessment)}</div><p class="drawer-label">CONFIDENCE: ${escapeHtml(label(brief.confidence))}</p><p class="drawer-label">EVIDENCE</p><ul class="investigation-list">${(brief.evidence || []).map((item) => `<li><strong>${escapeHtml(item.field)} = ${escapeHtml(item.observed)}</strong><span>${escapeHtml(item.interpretation)}</span></li>`).join("") || "<li>No evidence items returned.</li>"}</ul><p class="drawer-label">HYPOTHESES</p><ul class="investigation-list">${(brief.hypotheses || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>None returned.</li>"}</ul><p class="drawer-label">SAFE NEXT STEPS</p><ul class="investigation-list">${(brief.next_steps || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>None returned.</li>"}</ul><p class="drawer-label">LIMITATIONS</p><ul class="investigation-list">${(brief.limitations || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>None returned.</li>"}</ul><p class="form-note">${escapeHtml(notice)}</p>${investigationId ? `<div class="investigation-feedback"><p class="drawer-label">WAS THIS USEFUL?</p><label class="sr-only" for="investigationFeedbackNote">Optional feedback note</label><input id="investigationFeedbackNote" type="text" maxlength="2000" placeholder="Optional: what was missing or helpful?"><div><button class="row-action" data-feedback-rating="5" data-investigation-id="${escapeHtml(investigationId)}">Useful</button> <button class="row-action" data-feedback-rating="1" data-investigation-id="${escapeHtml(investigationId)}">Needs work</button></div></div>` : ""}`;
  result.querySelectorAll("[data-feedback-rating]").forEach((button) => button.addEventListener("click", () => submitInvestigationFeedback(button.dataset.investigationId, Number(button.dataset.feedbackRating), button)));
}
async function generateInvestigationBrief(alert) {
  const button = $("#investigateAlertButton");
  button.disabled = true;
  button.textContent = state.mode === "demo" ? "Sample only" : "Investigating…";
  if (state.mode === "demo") {
    renderInvestigationBrief({
      assessment: "Sample layout only: the demo does not call an AI model or analyze live telemetry. Configure an AI provider on your self-hosted API to generate a real brief.",
      confidence: "low",
      evidence: [{ field: "demo", observed: "synthetic event", interpretation: "This record is sample data and cannot establish a real threat." }],
      hypotheses: ["No operational conclusion can be drawn from this synthetic sample."],
      next_steps: ["Connect a deployed Vigilante API with AI investigation configured.", "Validate any generated evidence against source telemetry."],
      limitations: ["No model call was made."]
    }, "Sample only — not AI-generated.");
    button.disabled = false;
    button.textContent = "Preview sample brief";
    return;
  }
  try {
    const response = await apiRequest(`/api/v1/alerts/${encodeURIComponent(alert.id)}/investigation`, { method: "POST" });
    renderInvestigationBrief(response.brief, `${response.data_notice} Provider: ${response.provider}; model: ${response.model}.`, response.investigation_id);
  } catch (error) {
    const result = $("#investigationResult");
    if (result) result.innerHTML = `<p class="form-note">${escapeHtml(error.message)}</p>`;
  } finally {
    if (button.isConnected) {
      button.disabled = false;
      button.textContent = "Generate investigation brief";
    }
  }
}
async function submitInvestigationFeedback(investigationId, rating, button) {
  button.disabled = true;
  try {
    await apiRequest(`/api/v1/investigations/${encodeURIComponent(investigationId)}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rating, note: $("#investigationFeedbackNote").value.trim() })
    });
    button.closest(".investigation-feedback").innerHTML = "<p class=\"form-note\">Feedback recorded for evaluation. It does not train or change the AI model.</p>";
  } catch (error) {
    button.disabled = false;
    toast(`Could not record feedback: ${error.message}`);
  }
}
async function loadAiQualityMetrics() {
  const result = $("#aiQualityResult");
  const button = $("#loadAiQuality");
  if (state.mode !== "live") {
    result.textContent = "Connect a live API to view recorded evaluation metrics.";
    return;
  }
  button.disabled = true;
  result.textContent = "Loading metrics…";
  try {
    const metrics = await apiRequest("/api/v1/ai/quality");
    result.textContent = `${metrics.investigation_runs} investigation runs · ${metrics.rated_runs} rated · ${metrics.average_rating == null ? "No ratings yet" : `${metrics.average_rating}/5 average`}. Ratings are feedback, not an accuracy benchmark.`;
  } catch (error) {
    result.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}
function closeDrawer() {
  $("#detailDrawer").classList.remove("open");
  $("#detailDrawer").setAttribute("aria-hidden", "true");
  window.setTimeout(() => { $("#drawerBackdrop").hidden = true; }, 220);
  state.selectedAlert = null;
}
function openConnect() {
  $("#connectError").hidden = true;
  $("#connectModal").hidden = false;
  document.body.classList.add("modal-open");
  $("#apiBaseUrl").focus();
}
function closeConnect() {
  $("#connectModal").hidden = true;
  document.body.classList.remove("modal-open");
  $("#connectError").hidden = true;
}
function openProposalModal(alertId) {
  if (state.mode !== "live") { toast("Connect a live API before submitting response proposals."); return; }
  const alert = state.alerts.find((item) => String(item.id) === String(alertId));
  $("#proposalAlertId").value = alertId;
  $("#proposalTarget").value = alert && alert.payload ? (alert.payload.host || alert.payload.user || alert.payload.source_ip || "") : "";
  $("#proposalRationale").value = "";
  $("#proposalError").hidden = true;
  $("#proposalModal").hidden = false;
  document.body.classList.add("modal-open");
  $("#proposalActionType").focus();
}
function closeProposalModal() {
  $("#proposalModal").hidden = true;
  document.body.classList.remove("modal-open");
  $("#proposalError").hidden = true;
}
function openReviewModal(proposalId, decision) {
  state.reviewingProposalId = proposalId;
  $("#reviewProposalId").value = proposalId;
  $("#reviewDecision").value = decision;
  $("#reviewTitle").textContent = decision === "approve" ? "Approve response proposal" : "Reject response proposal";
  $("#reviewCopy").textContent = "Your decision is recorded for audit. This interface does not execute the proposed action.";
  $("#reviewReason").value = "";
  $("#reviewError").hidden = true;
  $("#reviewModal").hidden = false;
  document.body.classList.add("modal-open");
  $("#reviewReason").focus();
}
function closeReviewModal() {
  $("#reviewModal").hidden = true;
  document.body.classList.remove("modal-open");
  state.reviewingProposalId = null;
  $("#reviewError").hidden = true;
}
async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  const response = await fetch(`${state.apiBase}${path}`, { ...options, headers });
  const text = await response.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch { body = { detail: text || response.statusText }; }
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}
async function connectApi(event) {
  event.preventDefault();
  const button = $("#submitConnect");
  const error = $("#connectError");
  const base = $("#apiBaseUrl").value.trim().replace(/\/+$/, "");
  const username = $("#apiUsername").value.trim();
  const password = $("#apiPassword").value;
  if (!/^https:\/\//i.test(base) && !/^http:\/\/localhost(?::\d+)?$/i.test(base)) {
    error.textContent = "Use an HTTPS URL. HTTP is allowed only for localhost during development.";
    error.hidden = false;
    return;
  }
  state.apiBase = base;
  button.disabled = true;
  button.textContent = "Connecting…";
  error.hidden = true;
  try {
    const login = await fetch(`${base}/api/v1/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
    const loginBody = await login.json().catch(() => ({}));
    if (!login.ok || !loginBody.access_token) throw new Error(loginBody.detail || `Login failed (${login.status})`);
    state.token = loginBody.access_token;
    const [summary, alertData, caseData, proposalData, currentUser] = await Promise.all([
      apiRequest("/api/v1/dashboard/summary"),
      apiRequest("/api/v1/alerts?page_size=200"),
      apiRequest("/api/v1/cases"),
      apiRequest("/api/v1/response-proposals"),
      apiRequest("/api/v1/auth/me")
    ]);
    state.summary = summary;
    state.alerts = alertData.items || [];
    state.cases = caseData.items || [];
    state.proposals = proposalData.items || [];
    state.currentUser = currentUser;
    state.mode = "live";
    $("#apiPassword").value = "";
    closeConnect();
    renderAll();
    toast("Connected to the Vigilante API.");
  } catch (connectionError) {
    state.token = "";
    error.textContent = `${connectionError.message}. Check the API URL, account, HTTPS certificate, and CORS_ORIGINS setting.`;
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Connect securely";
  }
}
async function createCaseFromSelected() {
  const alert = state.selectedAlert;
  if (!alert) return;
  const title = `Investigation: ${alert.ai_summary || alert.id}`.slice(0, 240);
  try {
    let created;
    if (state.mode === "live") {
      created = await apiRequest("/api/v1/cases", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title, description: `Created from alert ${alert.id}.`, priority: alert.ai_severity || "medium", alert_ids: [alert.id] }) });
    } else {
      const caseNum = 19 + state.cases.length;
      created = { id: `CASE-${String(caseNum).padStart(3, "0")}`, case_number: caseNum, title, description: `Created from alert ${alert.id}.`, priority: alert.ai_severity || "medium", status: "open", alert_ids: [alert.id], updated_at: new Date().toISOString() };
      state.cases.unshift(created);
      alert.case_id = created.id;
    }
    renderAll();
    closeDrawer();
    toast(`Case ${created.case_number ? `#${created.case_number}` : "created"}.`);
  } catch (error) {
    toast(`Could not create case: ${error.message}`);
  }
}
async function updateSelectedAlertStatus() {
  const alert = state.selectedAlert;
  if (!alert) return;
  const nextStatus = $("#alertStatusSelect").value;
  const reason = $("#alertStatusReason").value.trim();
  if (reason.length < 3) { toast("Add a short reason for the status change."); return; }
  try {
    let updated;
    if (state.mode === "live") {
      updated = await apiRequest(`/api/v1/alerts/${encodeURIComponent(alert.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus, reason })
      });
      state.alerts = state.alerts.map((item) => String(item.id) === String(updated.id) ? updated : item);
    } else {
      alert.status = nextStatus;
      updated = alert;
    }
    renderAll();
    openDrawer(updated.id);
    toast(state.mode === "live" ? "Alert status saved to the API." : "Demo status saved in this browser only.");
  } catch (error) {
    toast(`Could not update alert: ${error.message}`);
  }
}
async function updateCaseStatus(caseId, nextStatus) {
  const existing = state.cases.find((item) => String(item.id) === String(caseId));
  if (!existing) return;
  try {
    let updated;
    if (state.mode === "live") {
      updated = await apiRequest(`/api/v1/cases/${encodeURIComponent(caseId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: nextStatus })
      });
    } else {
      updated = { ...existing, status: nextStatus, updated_at: new Date().toISOString() };
    }
    state.cases = state.cases.map((item) => String(item.id) === String(caseId) ? updated : item);
    renderAll();
    toast(state.mode === "live" ? "Case status saved to the API." : "Demo case status saved in this browser only.");
  } catch (error) {
    renderCases();
    toast(`Could not update case: ${error.message}`);
  }
}
async function submitProposal(event) {
  event.preventDefault();
  const error = $("#proposalError");
  const submit = $("#submitProposal");
  submit.disabled = true;
  error.hidden = true;
  try {
    const alertId = $("#proposalAlertId").value;
    const proposal = await apiRequest(`/api/v1/alerts/${encodeURIComponent(alertId)}/response-proposals`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_type: $("#proposalActionType").value, target_reference: $("#proposalTarget").value.trim(), rationale: $("#proposalRationale").value.trim() })
    });
    state.proposals.unshift(proposal);
    closeProposalModal();
    closeDrawer();
    renderAll();
    toast("Proposal submitted for independent review; no action was executed.");
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
}
async function submitReview(event) {
  event.preventDefault();
  const error = $("#reviewError");
  const submit = $("#submitReview");
  submit.disabled = true;
  error.hidden = true;
  try {
    const proposalId = $("#reviewProposalId").value;
    const updated = await apiRequest(`/api/v1/response-proposals/${encodeURIComponent(proposalId)}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision: $("#reviewDecision").value, reason: $("#reviewReason").value.trim() })
    });
    state.proposals = state.proposals.map((item) => item.id === updated.id ? updated : item);
    closeReviewModal();
    renderAll();
    toast(`Decision recorded: ${label(updated.status)}. No action was executed.`);
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    submit.disabled = false;
  }
}

$("#currentDate").textContent = new Intl.DateTimeFormat(undefined, { weekday: "short", month: "short", day: "numeric" }).format(new Date());
$$(".nav-item[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
$$('[data-page-link]').forEach((link) => link.addEventListener("click", (event) => { event.preventDefault(); showView(link.dataset.pageLink); }));
$$('[data-go]').forEach((button) => button.addEventListener("click", () => showView(button.dataset.go)));
$$("[data-open-connect]").forEach((button) => button.addEventListener("click", openConnect));
$("#connectButton").addEventListener("click", () => {
  if (state.mode === "live") {
    state.mode = "demo";
    state.token = "";
    state.summary = null;
    state.apiBase = "";
    state.currentUser = null;
    state.proposals = [];
    state.alerts = demoAlerts.map((alert) => ({ ...alert }));
    state.cases = demoCases.map((item) => ({ ...item }));
    renderAll();
    toast("Disconnected. Showing synthetic demo data.");
  } else openConnect();
});
$("#connectForm").addEventListener("submit", connectApi);
$("#loadAiQuality").addEventListener("click", loadAiQualityMetrics);
$("#proposalForm").addEventListener("submit", submitProposal);
$("#reviewForm").addEventListener("submit", submitReview);
$("#closeConnect").addEventListener("click", closeConnect);
$("#cancelConnect").addEventListener("click", closeConnect);
$("#connectModal").addEventListener("click", (event) => { if (event.target === $("#connectModal")) closeConnect(); });
$("#closeProposal").addEventListener("click", closeProposalModal);
$("#cancelProposal").addEventListener("click", closeProposalModal);
$("#proposalModal").addEventListener("click", (event) => { if (event.target === $("#proposalModal")) closeProposalModal(); });
$("#closeReview").addEventListener("click", closeReviewModal);
$("#cancelReview").addEventListener("click", closeReviewModal);
$("#reviewModal").addEventListener("click", (event) => { if (event.target === $("#reviewModal")) closeReviewModal(); });
$("#mobileMenu").addEventListener("click", () => {
  const open = !$("#sidebar").classList.contains("open");
  $("#sidebar").classList.toggle("open", open);
  $("#mobileMenu").setAttribute("aria-expanded", String(open));
});
$("#dismissBanner").addEventListener("click", () => {
  sessionStorage.setItem("vigilante-banner-dismissed", "1");
  $("#demoBanner").hidden = true;
});
$("#searchInput").addEventListener("input", (event) => { state.search = event.target.value; renderAlertTables(); });
$("#severityFilter").addEventListener("change", (event) => { state.severity = event.target.value; renderAlertTables(); });
$("#statusFilter").addEventListener("change", (event) => { state.status = event.target.value; renderAlertTables(); });
$("#casesBody").addEventListener("change", (event) => {
  const select = event.target.closest("[data-case-id]");
  if (select) updateCaseStatus(select.dataset.caseId, select.value);
});
document.addEventListener("click", (event) => {
  const reviewButton = event.target.closest("[data-review-id]");
  if (reviewButton) {
    openReviewModal(reviewButton.dataset.reviewId, reviewButton.dataset.reviewDecision);
    return;
  }
  const button = event.target.closest("[data-alert-id]");
  if (button) openDrawer(button.dataset.alertId);
});
$("#closeDrawer").addEventListener("click", closeDrawer);
$("#drawerBackdrop").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    if (!$("#connectModal").hidden) closeConnect();
    if (!$("#proposalModal").hidden) closeProposalModal();
    if (!$("#reviewModal").hidden) closeReviewModal();
    if ($("#detailDrawer").classList.contains("open")) closeDrawer();
    $("#sidebar").classList.remove("open");
  }
});
renderAll();
