"use strict";

const viewTitles = {
  overview: "Overview",
  protection: "Live shield",
  malware: "File protection",
  network: "Network & VPN",
  theft: "Theft protection",
  browser: "Browser guard",
  reports: "Action reports",
  settings: "Setup & settings",
};

const byId = (id) => document.getElementById(id);
let dashboardState = null;
let refreshTimer = null;

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

function pretty(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function showView(name) {
  if (!Object.prototype.hasOwnProperty.call(viewTitles, name)) return;
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === `view-${name}`);
  });
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.view === name);
  });
  byId("page-title").textContent = viewTitles[name];
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setPill(id, state, text) {
  const element = byId(id);
  if (!element) return;
  element.textContent = text;
  element.className = `status-pill ${state}`;
}

function statusError(section) {
  return section && typeof section === "object" && !Array.isArray(section) && section.error;
}

function renderDashboard(data) {
  dashboardState = data;
  const shield = data.shield;
  if (statusError(shield)) {
    setPill("shield-state", "error", "Unavailable");
    setPill("shield-panel-state", "error", "Unavailable");
    byId("shield-details").textContent = shield.error;
  } else {
    const running = Boolean(shield.running);
    setPill("shield-state", running ? "ok" : "off", running ? "Running" : "Stopped");
    setPill("shield-panel-state", running ? "ok" : "off", running ? "Running" : "Stopped");
    byId("shield-details").textContent = running
      ? `Process ID: ${shield.pid ?? "unknown"}${shield.blocked_count == null ? "" : ` · Blocked: ${shield.blocked_count}`}`
      : (shield.last_error || "The shield is not running.");
  }

  const startup = data.startup;
  if (statusError(startup)) {
    setPill("startup-state", "error", "Unavailable");
    byId("startup-details").textContent = startup.error;
  } else {
    setPill("startup-state", startup ? "ok" : "off", startup ? "Enabled" : "Disabled");
    byId("startup-details").textContent = startup || "Automatic startup is not installed.";
  }

  const scanners = data.malware?.scanners || {};
  const availableEngines = [
    scanners.clamav ? "ClamAV" : null,
    scanners.yara ? "YARA" : null,
  ].filter(Boolean);
  if (scanners.available) {
    setPill("scanner-state", "ok", `${availableEngines.length} available`);
    byId("scanner-details").textContent = availableEngines.join(" · ");
  } else {
    setPill("scanner-state", "warn", "No scanner");
    byId("scanner-details").textContent = "Install ClamAV or YARA to scan files.";
  }
  const monitor = data.malware?.monitor;
  if (statusError(monitor)) {
    byId("monitor-details").textContent = monitor.error;
  } else {
    byId("monitor-details").textContent = monitor?.running
      ? `Running · PID ${monitor.pid ?? "unknown"} · ${monitor.finding_count ?? 0} queued`
      : "Stopped";
  }

  const vpn = data.vpn;
  if (statusError(vpn)) {
    setPill("vpn-state", "error", "Unavailable");
    setPill("vpn-panel-state", "error", "Unavailable");
    byId("vpn-details").textContent = vpn.error;
  } else {
    const state = vpn?.state || {};
    const connected = Boolean(state.connected);
    const simulated = Boolean(state.simulated);
    setPill("vpn-state", connected ? (simulated ? "warn" : "ok") : "off", connected ? (simulated ? "Simulated" : "Connected") : "Disconnected");
    setPill("vpn-panel-state", connected ? (simulated ? "warn" : "ok") : "off", connected ? (simulated ? "Simulated" : "Connected") : "Disconnected");
    const where = state.country_name || state.profile || state.country_code || "No profile selected";
    byId("vpn-details").textContent = `${state.provider || "VPN"} · ${where}${state.server ? ` · ${state.server}` : ""}${simulated ? " · Simulation only; no network changes" : ""}`;
    const select = byId("vpn-country");
    const selected = select.value;
    select.innerHTML = '<option value="">Default / saved profile</option>';
    (vpn.available || []).forEach((item) => {
      const option = document.createElement("option");
      option.value = item.code;
      option.textContent = item.name;
      select.appendChild(option);
    });
    if ([...select.options].some((option) => option.value === selected)) select.value = selected;
  }

  const theft = data.theft?.armed;
  if (statusError(theft)) {
    setPill("theft-state", "error", "Unavailable");
    setPill("theft-panel-state", "error", "Unavailable");
  } else {
    const armed = Boolean(theft);
    setPill("theft-state", armed ? "warn" : "off", armed ? "Armed" : "Disarmed");
    setPill("theft-panel-state", armed ? "warn" : "off", armed ? "Armed" : "Disarmed");
  }

  renderItems("findings-list", "findings-count", data.findings, "finding");
  renderItems("quarantine-list", "quarantine-count", data.quarantine, "quarantine");

  const profile = data.profile;
  if (profile && !statusError(profile)) {
    byId("setup-notice").hidden = Boolean(profile.configured);
    if (!byId("profile-form").dataset.loaded) {
      byId("profile-name").value = profile.name || "";
      byId("profile-email").value = profile.alert_email || "";
      byId("ai-mode").value = profile.ai_mode || "offline";
      byId("rotation-time").value = profile.ip_rotation_time || "03:00";
      ["theft_protection", "reverse_shell_shield", "malware_scans", "ip_rotation", "consent_location", "consent_webcam"].forEach((name) => {
        byId("profile-form").elements.namedItem(name).checked = Boolean(profile[name]);
      });
      byId("profile-form").dataset.loaded = "true";
    }
  }
  [["malware", "malware-schedule-status"], ["ip", "ip-schedule-status"]].forEach(([name, id]) => {
    const state = data.schedules?.[name];
    byId(id).textContent = statusError(state)
      ? state.error
      : (state?.enabled ? "Enabled in Windows Task Scheduler." : "No scheduled task is enabled.");
  });
  byId("updated-at").textContent = `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

function renderItems(listId, countId, items, type) {
  const list = byId(listId);
  const count = byId(countId);
  if (!Array.isArray(items)) {
    list.innerHTML = `<div class="empty-state">${escapeHtml(items?.error || "Could not load items.")}</div>`;
    count.textContent = "—";
    return;
  }
  count.textContent = String(items.length);
  if (!items.length) {
    list.innerHTML = `<div class="empty-state">${type === "finding" ? "No findings awaiting review." : "Quarantine is empty."}</div>`;
    return;
  }
  list.innerHTML = items.map((item) => {
    const id = escapeHtml(item.id);
    const path = escapeHtml(item.path);
    const title = escapeHtml(`${item.classification || item.status || "File"} · ${item.signature || item.engine || "Local scan"}`);
    const stop = `<button class="mini-button danger" data-action="malware.stop-process" data-item-id="${id}" data-confirm="Stop every running process whose executable matches this finding? A false positive may close a legitimate program.">Stop process</button>`;
    const actions = type === "finding"
      ? `${stop}<button class="mini-button" data-action="quarantine.isolate" data-item-id="${id}" data-confirm="Move this detected file into Cypher quarantine?">Quarantine</button>`
      : item.status === "quarantined"
        ? `${stop}<button class="mini-button" data-action="quarantine.restore" data-item-id="${id}" data-confirm="Restore this file? It was detected and may still be unsafe.">Restore</button><button class="mini-button danger" data-action="quarantine.delete" data-item-id="${id}" data-confirm="Permanently delete this quarantined file? This cannot be undone.">Delete</button>`
        : "";
    return `<div class="data-row"><div class="data-main"><strong title="${path}">${title}</strong><small>${path}</small></div><div class="data-actions">${actions}</div></div>`;
  }).join("");
}

function renderReports(reports, targetId) {
  const target = byId(targetId);
  if (!Array.isArray(reports) || reports.length === 0) {
    target.innerHTML = `<div class="empty-state">${targetId === "recent-reports" ? "Your completed actions and their reports will appear here." : "No actions yet. Choose a tool to create your first report."}</div>`;
    return;
  }
  target.innerHTML = reports.map((report) => {
    const status = report.status === "completed" ? "completed" : "failed";
    const summary = report.error ? `Error: ${report.error}` : pretty(report.result);
    return `<article class="report-item"><div class="report-header"><strong>${escapeHtml(report.action)}</strong><span class="report-status ${status}">${status === "completed" ? "Completed" : "Failed"}</span><time class="report-time">${escapeHtml(new Date(report.completed_at).toLocaleString())}</time></div><pre class="report-result">${escapeHtml(summary)}</pre></article>`;
  }).join("");
}

async function loadDashboard() {
  const response = await fetch("/api/dashboard", { headers: { Accept: "application/json" }, cache: "no-store" });
  if (!response.ok) throw new Error(`Dashboard status failed (${response.status}).`);
  renderDashboard(await response.json());
}

async function verifyBackendVersion() {
  const button = document.querySelector('[data-action="malware.scan-machine"]');
  const warning = byId("backend-version-warning");
  try {
    const response = await fetch("/api/health", { headers: { Accept: "application/json" }, cache: "no-store" });
    const health = response.ok ? await response.json() : {};
    const supported = Number(health.api_version) >= 2;
    button.dataset.apiSupported = String(supported);
    button.disabled = !supported || button.dataset.working === "true";
    warning.hidden = supported;
  } catch {
    button.dataset.apiSupported = "false";
    button.disabled = true;
    warning.hidden = false;
  }
}

async function loadReports() {
  const response = await fetch("/api/reports", { headers: { Accept: "application/json" }, cache: "no-store" });
  if (!response.ok) throw new Error(`Could not load action reports (${response.status}).`);
  const reports = await response.json();
  renderReports(reports.slice(0, 5), "recent-reports");
  renderReports(reports, "all-reports");
}

async function loadUpdateStatus() {
  const response = await fetch("/api/updates", { headers: { Accept: "application/json" }, cache: "no-store" });
  if (!response.ok) throw new Error(`Could not check for updates (${response.status}).`);
  const status = await response.json();
  const dot = byId("update-dot");
  const button = byId("update-button");
  dot.hidden = !status.available;
  button.title = status.error
    ? `Update check unavailable: ${status.error}`
    : status.available
      ? (status.dirty
        ? "Update available; commit or stash local changes before updating."
        : `${status.behind} Cypher update(s) available`)
      : "Check for Cypher updates";
  button.setAttribute("aria-label", button.title);
}

async function updateNow() {
  const button = byId("update-button");
  if (!window.confirm("Check for updates and fast-forward this Cypher checkout if updates are available? Restart the dashboard after an update. Local changes will not be overwritten.")) return;
  button.disabled = true;
  try {
    const response = await fetch("/api/updates", {
      method: "POST",
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `Update failed (${response.status}).`);
    toast(data.updated
      ? `Updated to ${data.current}. Restart Cypher to load the changes.`
      : `Cypher is already up to date (${data.current}).`);
    await loadUpdateStatus();
  } catch (error) {
    toast(error.message || "Could not update Cypher.", true);
  } finally {
    button.disabled = false;
  }
}

function toast(message, failed = false) {
  const node = document.createElement("div");
  node.className = `toast${failed ? " error" : ""}`;
  node.textContent = message;
  byId("toast-region").appendChild(node);
  window.setTimeout(() => node.remove(), 4800);
}

function showReport(report) {
  byId("dialog-title").textContent = report.status === "completed" ? "Action completed" : "Action failed";
  const summary = report.error ? `Error: ${report.error}` : pretty(report.result);
  byId("dialog-report").innerHTML = `<div class="report-item"><div class="report-header"><strong>${escapeHtml(report.action)}</strong><span class="report-status ${report.status === "completed" ? "completed" : "failed"}">${report.status === "completed" ? "Completed" : "Failed"}</span></div><pre class="report-result">${escapeHtml(summary)}</pre><div class="detail-line">Started ${escapeHtml(new Date(report.started_at).toLocaleString())}<br>Finished ${escapeHtml(new Date(report.completed_at).toLocaleString())}</div></div>`;
  const dialog = byId("report-dialog");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else toast(`${report.action}: ${summary}`, report.status !== "completed");
}

function confirmationAccepted(button) {
  if (!button.dataset.confirm) return true;
  return window.confirm(button.dataset.confirm);
}

async function postAction(button, extra = {}) {
  if (!confirmationAccepted(button)) return;
  const action = button.dataset.action;
  const payload = { action, confirmed: Boolean(button.dataset.confirm), ...extra };
  if (action === "malware.scan") payload.path = byId("scan-path").value.trim() || null;
  if (action === "scan") {
    payload.path = byId("source-path").value.trim() || ".";
    payload.staged = button.dataset.staged === "true";
  }
  if (action === "redact") {
    payload.path = byId("redact-path").value.trim();
    payload.output = byId("redact-output").value.trim() || null;
  }
  if (action === "install-hook") payload.path = byId("hook-path").value.trim() || null;
  if (action === "explain") payload.item_id = byId("finding-id").value.trim();
  if (action === "ask") payload.question = byId("security-question").value.trim();
  if (action === "safe-run") payload.path = byId("safe-run-url").value.trim();
  if (action === "malware.schedule") {
    payload.interval = byId("malware-interval").value;
    payload.scheduled_at = byId("schedule-time").value || "03:00";
  }
  if (action === "ip.schedule") {
    payload.interval = byId("ip-schedule").value;
    payload.scheduled_at = byId("ip-schedule-time").value || "03:00";
  }
  if (action.startsWith("theft.safe-zones.")) payload.ssid = byId("safe-zone-ssid").value.trim();
  if (action === "vpn.connect") payload.country = byId("vpn-country").value || null;
  if (action.startsWith("quarantine.") || action === "malware.stop-process") payload.item_id = button.dataset.itemId;
  if (action === "shield.allow") payload.process_name = byId("process-name").value.trim();
  if (action === "shield.block-ip") payload.ip = byId("block-ip").value.trim();
  if (action === "ip.rotate") payload.dry_run = button.dataset.dryRun === "true";
  if (action === "theft.disarm") {
    payload.pin = byId("disarm-pin").value;
    if (!payload.pin) {
      toast("Enter your disarm PIN first.", true);
      return;
    }
  }

  const originalLabel = button.textContent;
  button.disabled = true;
  if (action === "malware.scan-machine") button.dataset.working = "true";
  button.textContent = "Working…";
  try {
    const response = await fetch("/api/actions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    const report = response.ok ? data : data.detail?.report;
    if (!report) throw new Error(data.detail?.message || `Action failed (${response.status}).`);
    if (action === "theft.disarm") byId("disarm-pin").value = "";
    if (action === "shield.allow") byId("process-name").value = "";
    if (action === "shield.block-ip") byId("block-ip").value = "";
    if (action === "theft.safe-zones.add" || action === "theft.safe-zones.remove") byId("safe-zone-ssid").value = "";
    if (action === "redact") byId("redact-output").value = "";
    toast(report.status === "completed" ? `${action} completed. Report is ready.` : `${action} failed. See the report.`, report.status !== "completed");
    showReport(report);
    await refreshAll();
  } catch (error) {
    toast(error.message || "Could not complete the action.", true);
  } finally {
    if (action === "malware.scan-machine") {
      button.dataset.working = "false";
      button.disabled = button.dataset.apiSupported !== "true";
    } else {
      button.disabled = false;
    }
    button.textContent = originalLabel;
  }
}

async function saveProfile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const values = new FormData(form);
  const payload = {
    action: "profile.save",
    name: values.get("name"),
    alert_email: values.get("alert_email"),
    ai_mode: values.get("ai_mode"),
    pin: values.get("pin") || null,
    ip_rotation_time: values.get("ip_rotation_time") || "03:00",
    theft_protection: form.elements.namedItem("theft_protection").checked,
    reverse_shell_shield: form.elements.namedItem("reverse_shell_shield").checked,
    malware_scans: form.elements.namedItem("malware_scans").checked,
    ip_rotation: form.elements.namedItem("ip_rotation").checked,
    consent_location: form.elements.namedItem("consent_location").checked,
    consent_webcam: form.elements.namedItem("consent_webcam").checked,
  };
  const button = form.querySelector('button[type="submit"]');
  const originalLabel = button.textContent;
  button.disabled = true;
  button.textContent = "Saving…";
  try {
    const response = await fetch("/api/actions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    const report = response.ok ? data : data.detail?.report;
    if (!report) throw new Error(data.detail?.message || `Save failed (${response.status}).`);
    byId("profile-pin").value = "";
    form.dataset.loaded = "";
    showReport(report);
    toast(report.status === "completed" ? "Settings saved. Report is ready." : "Settings were not saved. See the report.", report.status !== "completed");
    await refreshAll();
  } catch (error) {
    toast(error.message || "Could not save settings.", true);
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
}

async function refreshAll() {
  try {
    await Promise.all([loadDashboard(), loadReports(), loadUpdateStatus(), verifyBackendVersion()]);
  } catch (error) {
    toast(error.message || "Could not refresh the dashboard.", true);
  }
}

document.addEventListener("click", (event) => {
  const viewButton = event.target.closest("[data-view]");
  if (viewButton) {
    event.preventDefault();
    showView(viewButton.dataset.view);
    return;
  }
  const actionButton = event.target.closest("[data-action]");
  if (actionButton && !actionButton.disabled) postAction(actionButton);
});

byId("refresh-button").addEventListener("click", refreshAll);
byId("update-button").addEventListener("click", updateNow);
byId("profile-form").addEventListener("submit", saveProfile);
byId("close-report").addEventListener("click", () => byId("report-dialog").close());
byId("report-dialog").addEventListener("click", (event) => {
  if (event.target === byId("report-dialog")) byId("report-dialog").close();
});

refreshAll();
refreshTimer = window.setInterval(refreshAll, 20000);
window.addEventListener("beforeunload", () => window.clearInterval(refreshTimer));
