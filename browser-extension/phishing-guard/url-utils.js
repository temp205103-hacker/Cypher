"use strict";

globalThis.GuardSnitchUrlCheck = Object.freeze({
  hostForUrl(value) {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return null;
      }
      return parsed.hostname.toLowerCase().replace(/\.$/, "");
    } catch {
      return null;
    }
  },

  entryForUrl(value) {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return null;
      }
      const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
      return `${host}${parsed.pathname || "/"}`;
    } catch {
      return null;
    }
  },

  isPhishingUrl(value, phishingEntries) {
    const host = this.hostForUrl(value);
    if (!host || !(phishingEntries instanceof Set)) {
      return false;
    }

    const parsed = new URL(value);
    const paths = new Set([parsed.pathname || "/"]);
    let pathPrefix = "";
    for (const segment of (parsed.pathname || "/").split("/").filter(Boolean)) {
      pathPrefix += `/${segment}`;
      paths.add(`${pathPrefix}/`);
    }
    paths.add("/");

    const hosts = [host];
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) && !host.startsWith("[")) {
      const labels = host.split(".");
      for (let index = 1; index < labels.length - 1; index += 1) {
        hosts.push(labels.slice(index).join("."));
      }
    }
    return hosts.some((candidateHost) =>
      Array.from(paths).some((path) => phishingEntries.has(`${candidateHost}${path}`))
    );
  }
});
