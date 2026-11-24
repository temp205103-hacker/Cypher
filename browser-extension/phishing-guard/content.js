"use strict";

(() => {
  if (window.__cypherPhishingGuardLoaded) {
    return;
  }
  window.__cypherPhishingGuardLoaded = true;

  let phishingEntries = new Set();
  let listLoaded = false;
  let warningOpen = false;

  function isPhishingLink(anchor) {
    return CypherUrlCheck.isPhishingUrl(anchor.href, phishingEntries);
  }

  function scanLink(anchor) {
    if (isPhishingLink(anchor)) {
      anchor.dataset.cypherPhishing = "true";
    } else {
      delete anchor.dataset.cypherPhishing;
    }
  }

  function scanNode(node) {
    if (!(node instanceof Element)) {
      return;
    }
    if (node.matches("a[href]")) {
      scanLink(node);
    }
    for (const anchor of node.querySelectorAll("a[href]")) {
      scanLink(anchor);
    }
  }

  function displayUrl(value) {
    try {
      const parsed = new URL(value);
      return `${parsed.origin}${parsed.pathname}`;
    } catch {
      return value;
    }
  }

  function recordIncident(url, result, trigger) {
    let domain = "";
    try {
      domain = new URL(url).hostname;
    } catch {
      return;
    }
    const evidence = Array.isArray(result?.evidence)
      ? result.evidence
        .filter((item) => item && typeof item.evidence === "string")
        .slice(0, 20)
        .map((item) => ({ evidence: item.evidence.slice(0, 500) }))
      : [];
    chrome.runtime.sendMessage({
      type: "record-phish-incident",
      incident: {
        domain,
        verdict: result?.verdict || "Phishing",
        risk_score: Number(result?.risk_score) || 100,
        evidence: evidence.length
          ? evidence
          : [{ evidence: "URL matched the locally cached phishing feed." }],
        trigger
      }
    });
  }

  function showWarning(url, details = {}) {
    if (warningOpen) {
      return;
    }
    warningOpen = true;

    const host = document.createElement("div");
    host.style.cssText =
      "all:initial!important;position:fixed!important;inset:0!important;" +
      "z-index:2147483647!important;";
    const shadow = host.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .backdrop {
          align-items: center; background: rgba(15, 23, 42, .78);
          display: flex; font: 16px/1.5 system-ui, sans-serif;
          inset: 0; justify-content: center; padding: 20px; position: fixed;
        }
        .dialog {
          background: #fff; border-radius: 12px; box-shadow: 0 16px 60px #0008;
          box-sizing: border-box;           color: #172033; max-width: 520px;
          padding: 24px; width: 100%;
        }
        h2 { color: #a51d24; font-size: 22px; margin: 0 0 10px; }
        p { margin: 10px 0; }
        .url {
          background: #f1f3f6; border-radius: 6px; overflow-wrap: anywhere;
          padding: 10px;
        }
        .buttons { display: flex; gap: 12px; justify-content: flex-end; margin-top: 20px; }
        button {
          border: 0; border-radius: 6px; cursor: pointer; font: inherit;
          font-weight: 650; padding: 9px 18px;
        }
        .block { background: #e7ebf0; color: #172033; }
        .proceed { background: #fff; color: #a51d24; }
        button:focus-visible { outline: 3px solid #2563eb; outline-offset: 2px; }
      </style>
      <div class="backdrop">
        <section class="dialog" role="alertdialog" aria-modal="true"
          aria-labelledby="guard-title" aria-describedby="guard-message">
          <h2 id="guard-title"></h2>
          <p id="guard-message"></p>
          <p class="url"></p>
          <p class="reason"></p>
          <div class="buttons">
            <button class="block" type="button">No, block</button>
            ${details.canProceed ? '<button class="proceed" type="button">Proceed anyway</button>' : ""}
          </div>
        </section>
      </div>
    `;
    shadow.querySelector(".url").textContent = displayUrl(url);
    shadow.querySelector("#guard-title").textContent =
      details.source === "local"
        ? "Cypher flagged this link"
        : details.source === "unavailable"
          ? "This link could not be checked"
          : "Phishing link detected";
    shadow.querySelector("#guard-message").textContent =
      details.source === "feed"
        ? "This URL matches Cypher's cached phishing list. It was stopped before navigation."
        : details.source === "unavailable"
          ? "The local Cypher service did not respond. Continue only if you trust this link."
          : "Cypher stopped this click before navigation because the local URL analysis found risk indicators.";
    shadow.querySelector(".reason").textContent = details.explanation || "";

    function closeWarning() {
      warningOpen = false;
      host.remove();
    }

    shadow.querySelector(".block").addEventListener("click", closeWarning);
    if (details.canProceed) {
      shadow.querySelector(".proceed").addEventListener("click", () => {
        let host = "";
        try {
          host = new URL(url).hostname;
        } catch {
          host = "";
        }
        if (!host || !window.confirm(`Proceed to ${displayUrl(url)}? Cypher will record the domain.`)) {
          return;
        }
        chrome.runtime.sendMessage(
          { type: "phish-proceed", domain: host },
          (result) => {
            if (chrome.runtime.lastError || !result?.ok) {
              shadow.querySelector(".reason").textContent =
                result?.error || "Cypher could not record the override.";
              return;
            }
            window.location.assign(url);
          }
        );
      });
    }
    shadow.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeWarning();
      }
    });

    (document.documentElement || document).appendChild(host);
    shadow.querySelector(".block").focus();
  }

  function anchorFromEvent(event) {
    for (const node of event.composedPath()) {
      if (node instanceof HTMLAnchorElement && node.href) {
        return node;
      }
    }
    return null;
  }

  function handleLinkActivation(event) {
    if (!listLoaded || event.defaultPrevented) {
      return;
    }
    const anchor = anchorFromEvent(event);
    if (!anchor) {
      return;
    }
    if (isPhishingLink(anchor)) {
      event.preventDefault();
      event.stopImmediatePropagation();
      recordIncident(
        anchor.href,
        {
          verdict: "Phishing",
          risk_score: 100,
          evidence: [{ evidence: "URL matched the locally cached phishing feed." }]
        },
        "extension-feed-click"
      );
      showWarning(anchor.href, { source: "feed" });
      return;
    }
    if (
      event.button !== 0 ||
      event.ctrlKey ||
      event.metaKey ||
      event.shiftKey ||
      event.altKey ||
      anchor.hasAttribute("download") ||
      (anchor.target && anchor.target !== "_self")
    ) {
      return;
    }
    let protocol = "";
    try {
      protocol = new URL(anchor.href).protocol;
    } catch {
      return;
    }
    if (!["http:", "https:"].includes(protocol)) {
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    chrome.runtime.sendMessage(
      { type: "check-phish-url", url: anchor.href },
      (result) => {
        if (chrome.runtime.lastError) {
          showWarning(anchor.href, {
            source: "unavailable",
            canProceed: true,
            explanation: "The local extension service did not respond."
          });
          return;
        }
        if (result?.configured && result.error) {
          showWarning(anchor.href, {
            source: "unavailable",
            canProceed: true,
            explanation: "Check that the Cypher dashboard is running and the token is current."
          });
          return;
        }
        if (result?.configured === false) {
          window.location.assign(anchor.href);
          return;
        }
        if (Number(result?.risk_score) >= 45) {
          recordIncident(anchor.href, result, "extension-click");
          showWarning(anchor.href, {
            source: "local",
            canProceed: true,
            explanation: result.explanation || "The local check found suspicious URL indicators."
          });
          return;
        }
        window.location.assign(anchor.href);
      }
    );
  }

  document.addEventListener("click", handleLinkActivation, true);
  document.addEventListener("auxclick", (event) => {
    if (event.button === 1) {
      handleLinkActivation(event);
    }
  }, true);

  const observer = new MutationObserver((mutations) => {
    if (!listLoaded) {
      return;
    }
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        scanNode(node);
      }
      if (mutation.type === "attributes" && mutation.target instanceof HTMLAnchorElement) {
        scanLink(mutation.target);
      }
    }
  });
  observer.observe(document, {
    attributes: true,
    attributeFilter: ["href"],
    childList: true,
    subtree: true
  });

  chrome.storage.local.get(["phishingEntries"], (data) => {
    if (chrome.runtime.lastError) {
      return;
    }
    phishingEntries = new Set(
      Array.isArray(data.phishingEntries) ? data.phishingEntries : []
    );
    listLoaded = true;
    scanNode(document.documentElement);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.phishingEntries) {
      return;
    }
    phishingEntries = new Set(
      Array.isArray(changes.phishingEntries.newValue)
        ? changes.phishingEntries.newValue
        : []
    );
    listLoaded = true;
    scanNode(document.documentElement);
  });
})();
