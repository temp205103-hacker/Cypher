"use strict";

importScripts("url-utils.js");

const FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const UPDATE_ALARM = "cypher-phishing-feed";
const UPDATE_INTERVAL_MINUTES = 360;
const RULE_ID_START = 1;
const MAX_DYNAMIC_RULES = 5000;

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

chrome.runtime.onInstalled.addListener(() => {
  scheduleFeedRefresh();
  void refreshFeed();
});

chrome.runtime.onStartup.addListener(() => {
  scheduleFeedRefresh();
  void refreshFeed();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === UPDATE_ALARM) {
    void refreshFeed();
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "refresh-phishing-feed") {
    return false;
  }
  refreshFeed().then(sendResponse);
  return true;
});
