"use strict";

importScripts("url-utils.js");

const FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const UPDATE_ALARM = "cypher-phishing-feed";
const LOCAL_UPDATE_ALARM = "cypher-local-phishing-list";
const UPDATE_INTERVAL_MINUTES = 360;
const RULE_ID_START = 1;
const MAX_DYNAMIC_RULES = 4000;
const LOCAL_RULE_ID_START = 5001;
const MAX_LOCAL_RULES = 1000;
const LOCAL_API_HOST = "http://127.0.0.1";
const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const PROCEED_DURATION_MS = 5 * 60 * 1000;

async function installBlockingRules(entries) {
  const selected = Array.from(entries).slice(0, MAX_DYNAMIC_RULES);
  const rules = selected.map((entry, index) => ({
    id: RULE_ID_START + index,
    priority: 1,
    action: { type: "block" },
    condition: {
      urlFilter: `||${entry.replace(/[\\*^|]/g, "\\$&")}`,
      resourceTypes: ["main_frame", "sub_frame", "script", "xmlhttprequest", "other"]
    }
  }));
  const currentRules = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: currentRules
      .filter((rule) => rule.id >= RULE_ID_START && rule.id < RULE_ID_START + MAX_DYNAMIC_RULES)
      .map((rule) => rule.id),
    addRules: rules
  });
  return selected.length;
}

async function refreshFeed() {
  try {
    const response = await fetch(FEED_URL, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Feed request failed with HTTP ${response.status}`);
    }

    const text = await response.text();
    const entries = new Set();
    for (const line of text.split(/\r?\n/)) {
      const value = line.trim();
      if (!value || value.startsWith("#")) {
        continue;
      }
      const entry = CypherUrlCheck.entryForUrl(value);
      if (entry) {
        entries.add(entry);
      }
    }
    if (entries.size === 0) {
      throw new Error("The feed contained no usable phishing URLs");
    }

    const blockedRuleCount = await installBlockingRules(entries);
    await chrome.storage.local.set({
      phishingEntries: Array.from(entries),
      blockedRuleCount,
      feedUpdatedAt: Date.now(),
      feedError: ""
    });
    return { ok: true, entryCount: blockedRuleCount };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await chrome.storage.local.set({ feedError: message });
    return { ok: false, error: message };
  }
}

function scheduleFeedRefresh() {
  chrome.alarms.create(UPDATE_ALARM, {
    periodInMinutes: UPDATE_INTERVAL_MINUTES
  });
}

function scheduleLocalRefresh() {
  chrome.alarms.create(LOCAL_UPDATE_ALARM, { periodInMinutes: 5 });
}

async function installLocalRules(entries) {
  const { localBypasses = {} } = await chrome.storage.local.get("localBypasses");
  const now = Date.now();
  const domains = Array.from(new Set(entries))
    .filter((entry) => DOMAIN_PATTERN.test(entry))
    .filter((entry) => !(Number(localBypasses[entry]) > now))
    .sort()
    .slice(0, MAX_LOCAL_RULES);
  const rules = domains.map((domain, index) => ({
    id: LOCAL_RULE_ID_START + index,
    priority: 2,
    action: {
      type: "redirect",
      redirect: {
        extensionPath: `/warning.html?domain=${encodeURIComponent(domain)}`
      }
    },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: ["main_frame"]
    }
  }));
  const currentRules = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: currentRules
      .filter((rule) => rule.id >= LOCAL_RULE_ID_START && rule.id < LOCAL_RULE_ID_START + MAX_LOCAL_RULES)
      .map((rule) => rule.id),
    addRules: rules
  });
  return domains;
}

async function refreshLocalBlocklist() {
  const settings = await chrome.storage.local.get(["localApiToken", "dashboardPort"]);
  const token = String(settings.localApiToken || "").trim();
  const port = Number(settings.dashboardPort || 8787);
  if (!token || !Number.isInteger(port) || port < 1 || port > 65535) {
    await chrome.storage.local.set({
      localBlockError: "Connect the extension to Cypher from the local dashboard."
    });
    return { ok: false, error: "Local extension connection is not configured." };
  }
  try {
    const response = await fetch(
      `${LOCAL_API_HOST}:${port}/api/phish/blocked-domains`,
      {
        cache: "no-store",
        headers: { "X-Cypher-Token": token }
      }
    );
    if (!response.ok) {
      throw new Error(`Cypher returned HTTP ${response.status}`);
    }
    const data = await response.json();
    const domains = Array.isArray(data.domains) ? data.domains : [];
    const installed = await installLocalRules(domains);
    await chrome.storage.local.set({
      localBlockedDomains: installed,
      localWatchEnabled: Boolean(data.watch_enabled),
      localBlockUpdatedAt: Date.now(),
      localBlockError: ""
    });
    return { ok: true, blockedDomainCount: installed.length };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await chrome.storage.local.set({ localBlockError: message });
    return { ok: false, error: message };
  }
}

async function checkUrlWithCypher(url) {
  const settings = await chrome.storage.local.get([
    "localApiToken",
    "dashboardPort",
    "localWatchEnabled"
  ]);
  const token = String(settings.localApiToken || "").trim();
  const port = Number(settings.dashboardPort || 8787);
  if (
    !token ||
    !settings.localWatchEnabled ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  ) {
    return { configured: false };
  }
  try {
    const response = await fetch(`${LOCAL_API_HOST}:${port}/api/phish/check`, {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-Cypher-Token": token
      },
      body: JSON.stringify({ url })
    });
    if (!response.ok) {
      throw new Error(`Cypher returned HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    return {
      configured: true,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function recordIncident(incident) {
  const settings = await chrome.storage.local.get(["localApiToken", "dashboardPort"]);
  const token = String(settings.localApiToken || "").trim();
  const port = Number(settings.dashboardPort || 8787);
  if (!token || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "Local Cypher connection is not configured." };
  }
  try {
    const response = await fetch(`${LOCAL_API_HOST}:${port}/api/phish/incident`, {
      method: "POST",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "X-Cypher-Token": token
      },
      body: JSON.stringify(incident)
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || `Cypher returned HTTP ${response.status}`);
    }
    return { ok: true, id: data.id };
  } catch (error) {
    return {
      ok: false,
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

async function allowDomainTemporarily(domain) {
  if (!DOMAIN_PATTERN.test(domain)) {
    throw new Error("The blocked domain is invalid.");
  }
  const data = await chrome.storage.local.get([
    "localBlockedDomains",
    "localBypasses",
    "phishProceedLog"
  ]);
  const domains = Array.isArray(data.localBlockedDomains) ? data.localBlockedDomains : [];
  const bypasses = data.localBypasses || {};
  const locallyBlocked = domains.includes(domain);
  if (locallyBlocked) {
    bypasses[domain] = Date.now() + PROCEED_DURATION_MS;
  }
  const log = Array.isArray(data.phishProceedLog) ? data.phishProceedLog : [];
  log.push({ domain, timestamp: new Date().toISOString(), action: "temporary-proceed" });
  await chrome.storage.local.set({ localBypasses: bypasses, phishProceedLog: log.slice(-50) });
  if (locallyBlocked) {
    await installLocalRules(domains);
  }
  return { ok: true, locallyBlocked };
}

chrome.runtime.onInstalled.addListener(() => {
  scheduleFeedRefresh();
  scheduleLocalRefresh();
  void refreshFeed();
  void refreshLocalBlocklist();
});

chrome.runtime.onStartup.addListener(() => {
  scheduleFeedRefresh();
  scheduleLocalRefresh();
  void refreshFeed();
  void refreshLocalBlocklist();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === UPDATE_ALARM) {
    void refreshFeed();
  } else if (alarm.name === LOCAL_UPDATE_ALARM) {
    void refreshLocalBlocklist();
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "refresh-phishing-feed") {
    refreshFeed().then(sendResponse);
    return true;
  }
  if (message?.type === "refresh-local-phishing-list") {
    refreshLocalBlocklist().then(sendResponse);
    return true;
  }
  if (message?.type === "configure-local-service") {
    const token = String(message.token || "").trim();
    const port = Number(message.port || 8787);
    if (token.length < 32 || !Number.isInteger(port) || port < 1 || port > 65535) {
      sendResponse({ ok: false, error: "Enter the Cypher token and a valid port." });
      return false;
    }
    chrome.storage.local.set({ localApiToken: token, dashboardPort: port })
      .then(refreshLocalBlocklist)
      .then(sendResponse);
    return true;
  }
  if (message?.type === "check-phish-url") {
    checkUrlWithCypher(String(message.url || "")).then(sendResponse);
    return true;
  }
  if (message?.type === "record-phish-incident") {
    recordIncident(message.incident || {}).then(sendResponse);
    return true;
  }
  if (message?.type === "phish-proceed") {
    allowDomainTemporarily(String(message.domain || ""))
      .then(sendResponse)
      .catch((error) => sendResponse({
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      }));
    return true;
  }
  return false;
});
