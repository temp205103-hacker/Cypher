"use strict";

const statusElement = document.getElementById("status");
const refreshButton = document.getElementById("refresh");

function renderStatus(data) {
  const count = Number(data.blockedRuleCount) || 0;
  const updatedAt = Number(data.feedUpdatedAt) || 0;
  const ageHours = updatedAt ? (Date.now() - updatedAt) / 3_600_000 : Infinity;

  if (count === 0) {
    statusElement.textContent =
      data.feedError
        ? `No phishing blocking rules are active. Update error: ${data.feedError}`
        : "No phishing blocking rules are active. Update the list to enable protection.";
    return;
  }

  const updated = new Date(updatedAt).toLocaleString();
  if (ageHours > 24) {
    statusElement.textContent =
      `Warning: phishing URL list is stale (last updated ${updated}). ` +
      "Known matches are still blocked, but recent phishing sites may be missed.";
  } else if (data.feedError) {
    statusElement.textContent =
      `Using cached blocking rules (${count} URL entries; last updated ${updated}). ` +
      "The latest update failed.";
  } else {
    statusElement.textContent =
      `Protection active: ${count} phishing URL rules block matching requests, ` +
      `including address-bar navigation. Last updated ${updated}.`;
  }
}

function loadStatus() {
  chrome.storage.local.get(
    ["phishingEntries", "feedUpdatedAt", "feedError"],
    renderStatus
  );
}

refreshButton.addEventListener("click", () => {
  refreshButton.disabled = true;
  statusElement.textContent = "Updating phishing list...";
  chrome.runtime.sendMessage({ type: "refresh-phishing-feed" }, (result) => {
    refreshButton.disabled = false;
    if (chrome.runtime.lastError) {
      statusElement.textContent =
        `Could not update the phishing list: ${chrome.runtime.lastError.message}`;
      return;
    }
    if (!result?.ok) {
      loadStatus();
      return;
    }
    loadStatus();
  });
});

chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "local") {
    loadStatus();
  }
});

loadStatus();
