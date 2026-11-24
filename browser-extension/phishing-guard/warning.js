"use strict";

const params = new URLSearchParams(window.location.search);
const domain = (params.get("domain") || "").toLowerCase();
const domainPattern =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const domainElement = document.getElementById("domain");
const whyElement = document.getElementById("why");

domainElement.textContent = domainPattern.test(domain) ? domain : "(unknown domain)";

if (domainPattern.test(domain)) {
  chrome.runtime.sendMessage({
    type: "record-phish-incident",
    incident: {
      domain,
      verdict: "Phishing",
      risk_score: 100,
      evidence: [{ evidence: "Domain matched the local blocklist before navigation." }],
      trigger: "extension-local-block"
    }
  });
}

document.getElementById("back").addEventListener("click", () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.replace("about:blank");
  }
});

document.getElementById("why-button").addEventListener("click", () => {
  whyElement.textContent =
    "This exact domain is in Cypher's local blocked-domain list. The redirect happened in the browser before the requested page loaded. URL heuristics alone are not used to silently add domains to this list.";
  whyElement.hidden = false;
});

document.getElementById("proceed").addEventListener("click", () => {
  if (!domainPattern.test(domain)) {
    whyElement.textContent = "Cypher could not verify the blocked domain for a safe override.";
    whyElement.hidden = false;
    return;
  }
  if (!window.confirm(`Proceed to https://${domain}/? The local block will be bypassed for five minutes.`)) {
    return;
  }
  chrome.runtime.sendMessage(
    { type: "phish-proceed", domain },
    (result) => {
      if (chrome.runtime.lastError || !result?.ok) {
        whyElement.textContent = result?.error || "Cypher could not record the override.";
        whyElement.hidden = false;
        return;
      }
      window.location.assign(`https://${domain}/`);
    }
  );
});
