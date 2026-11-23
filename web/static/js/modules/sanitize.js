/**
 * SNMK Enterprise Web UI — DOM Sanitization & Safe Element Construction
 * Guarantees zero DOM-based XSS when injecting vulnerability descriptions,
 * payloads, endpoints, or unescaped agent responses into the DOM.
 */

const ESCAPE_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
};

export function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str).replace(/[&<>"'/]/g, (match) => ESCAPE_MAP[match]);
}

export function sanitizeUrl(url) {
  if (!url) return "#";
  const trimmed = String(url).trim();
  const lower = trimmed.toLowerCase();
  if (
    lower.startsWith("javascript:") ||
    lower.startsWith("data:") ||
    lower.startsWith("vbscript:")
  ) {
    return "about:blank";
  }
  return trimmed;
}

export function createSafeElement(tag, attributes = {}, textContent = "") {
  const el = document.createElement(tag);
  Object.entries(attributes).forEach(([k, v]) => {
    if (k === "href" || k === "src") {
      el.setAttribute(k, sanitizeUrl(v));
    } else if (k === "className") {
      el.className = v;
    } else {
      el.setAttribute(k, v);
    }
  });
  if (textContent) {
    el.textContent = textContent;
  }
  return el;
}
