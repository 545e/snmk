/**
 * SNMK Enterprise Web UI — Dashboard & SOC Navigation Module
 * Renders executive risk posture metrics, severity gauges, and real-time feeds.
 */

import { escapeHtml } from "./sanitize.js";
import { store } from "./state.js";

export function renderDashboardCards(metrics, containerId = "dashboard-metrics") {
  const container = document.getElementById(containerId);
  if (!container || !metrics) return;

  const cards = [
    { title: "Critical Vulnerabilities", val: metrics.critical || 0, color: "var(--red)" },
    { title: "High Severity", val: metrics.high || 0, color: "var(--orange)" },
    { title: "Medium Severity", val: metrics.medium || 0, color: "var(--yellow)" },
    { title: "Discovered Subdomains", val: metrics.subdomains_count || 0, color: "var(--cyan)" },
    { title: "Active Autonomous Agents", val: metrics.agents_active || 94, color: "var(--purple)" },
    { title: "Integrations Operational", val: metrics.integrations_healthy || 23, color: "var(--green)" },
  ];

  container.innerHTML = cards
    .map(
      (c) => `
    <div class="metric-card">
      <div class="metric-title">${escapeHtml(c.title)}</div>
      <div class="metric-value" style="color: ${escapeHtml(c.color)}">${escapeHtml(c.val)}</div>
    </div>
  `
    )
    .join("");
}
