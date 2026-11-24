"use strict";

(() => {
  if (window.__guardSnitchPhishingGuardLoaded) {
    return;
  }
  window.__guardSnitchPhishingGuardLoaded = true;

  let phishingEntries = new Set();
  let listLoaded = false;
  let warningOpen = false;

  function isPhishingLink(anchor) {
    return GuardSnitchUrlCheck.isPhishingUrl(anchor.href, phishingEntries);
  }

  function scanLink(anchor) {
    if (isPhishingLink(anchor)) {
      anchor.dataset.guardsnitchPhishing = "true";
    } else {
      delete anchor.dataset.guardsnitchPhishing;
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

  function showWarning(url) {
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
          box-sizing: border-box; color: #172033; max-width: 520px;
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
        button:focus-visible { outline: 3px solid #2563eb; outline-offset: 2px; }
      </style>
      <div class="backdrop">
        <section class="dialog" role="alertdialog" aria-modal="true"
          aria-labelledby="guard-title" aria-describedby="guard-message">
          <h2 id="guard-title">Phishing link detected</h2>
          <p id="guard-message">This link matches GuardSnitch.ai's phishing list.
            It may be unsafe to open.</p>
          <p class="url"></p>
          <div class="buttons">
            <button class="block" type="button">No, block</button>
          </div>
        </section>
      </div>
    `;
    shadow.querySelector(".url").textContent = displayUrl(url);

    function closeWarning() {
      warningOpen = false;
      host.remove();
    }

    shadow.querySelector(".block").addEventListener("click", closeWarning);
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
    if (!anchor || !isPhishingLink(anchor)) {
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();
    showWarning(anchor.href);
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
