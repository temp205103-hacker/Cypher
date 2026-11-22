"use strict";

importScripts("url-utils.js");

const FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";
const UPDATE_ALARM = "guardsnitch-phishing-feed";
const UPDATE_INTERVAL_MINUTES = 360;

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
      const entry = GuardSnitchUrlCheck.entryForUrl(value);
      if (entry) {
        entries.add(entry);
      }
    }
    if (entries.size === 0) {
      throw new Error("The feed contained no usable phishing URLs");
    }

    await chrome.storage.local.set({
      phishingEntries: Array.from(entries),
      feedUpdatedAt: Date.now(),
      feedError: ""
    });
    return { ok: true, entryCount: entries.size };
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
