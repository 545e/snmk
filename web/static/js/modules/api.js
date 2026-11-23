/**
 * SNMK Enterprise Web UI — ES6 API Client Bridge
 * Wraps window.apiFetch into clean promise-based async functions with typed return helpers.
 */

export async function fetchJson(endpoint, options = {}) {
  if (typeof window.apiFetch === "function") {
    const res = await window.apiFetch(endpoint, options);
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody.detail || `Request failed with status ${res.status}`);
    }
    return res.json();
  }
  const res = await fetch(endpoint, options);
  return res.json();
}

export async function getScans() {
  return fetchJson("/api/scans");
}

export async function getSubdomains(scanId = null) {
  const url = scanId ? `/api/subdomains/${encodeURIComponent(scanId)}` : "/api/subdomains";
  return fetchJson(url);
}

export async function getFindings(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = query ? `/api/findings?${query}` : "/api/findings";
  return fetchJson(url);
}

export async function getAgentsSummary() {
  return fetchJson("/api/agents/summary");
}

export async function getIntegrationsSummary() {
  return fetchJson("/api/integrations/summary");
}
