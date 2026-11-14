import { api, qs } from "../api.js";
import { severityBar, trendChart } from "../charts.js";
import { baseName, empty, fmtDuration, fmtTime, h, mount, statusBadge, table } from "../dom.js";
import { categoryCards, incompleteBanner, riskCard } from "./components.js";

export function toolStrip(tools) {
  return h("div", { class: "grid grid-2" }, tools.map((t) => h("div", { class: "card row" },
    h("strong", { text: t.name === "trivy" ? "Trivy" : "Gitleaks" }),
    t.installed ? h("span", { class: "badge st-ok", text: "Installed" }) : h("span", { class: "badge st-bad", text: "Not installed" }),
    t.installed ? h("span", { class: "muted", text: t.version ? `version ${t.version}` : "version unknown" })
      : h("span", {}, "Install with ", h("code", { class: "mono", text: t.install_hint })))));
}

export const scanRow = (s) => h("tr", {},
  h("td", {}, h("a", { href: `#/scans/${s.id}`, text: `#${s.id}` })),
  h("td", { class: "small", text: fmtTime(s.started_at ?? s.created_at) }),
  h("td", { class: "wrap", title: s.target_path, text: baseName(s.target_path) }),
  h("td", { class: "wrap", text: s.label ?? "—" }),
  h("td", {}, statusBadge(s.status)),
  h("td", { class: "num", text: fmtDuration(s.elapsed_ms) }),
  h("td", { class: "num" }, s.incomplete ? h("span", { class: "badge st-warn", text: "Incomplete" })
    : (s.status === "completed" ? String(s.findings_total) : "—")),
  h("td", { class: "num", text: s.risk_score ?? "—" }));
export const SCAN_HEADERS = ["Scan", "Time", "Target", "Label", "Status", "Duration", "Findings", "Risk"];

export async function dashboard(root) {
  const [tools, scans] = await Promise.all([api.get("/system/tools"), api.get("/scans" + qs({ limit: 50 }))]);
  const newBtn = h("a", { class: "btn primary", href: "#/scans/new", text: "New scan" });
  const head = h("div", { class: "page-head" },
    h("div", {}, h("h1", { text: "Dashboard" }), h("p", { class: "sub", text: "Local scan results from Trivy and Gitleaks." })), newBtn);
  if (!scans.items.length) {
    mount(root, head, toolStrip(tools), h("div", { class: "card section" },
      empty("No scans yet", "Start your first scan to see findings here.", h("a", { class: "btn primary", href: "#/scans/new", text: "New scan" }))));
    return;
  }
  const latest = await api.get(`/scans/${scans.items[0].id}`);
  const sameTarget = scans.items.filter((s) => s.target_path === latest.target_path && !["queued", "running"].includes(s.status)).slice(0, 10).reverse();
  const busy = ["queued", "running"].includes(latest.status);
  mount(root, head, toolStrip(tools),
    h("section", { class: "section" },
      h("div", { class: "row" }, h("h2", {}, "Latest scan — ", h("a", { href: `#/scans/${latest.id}`, text: `#${latest.id} ${baseName(latest.target_path)}` })), statusBadge(latest.status)),
      h("p", { class: "sub small", text: `${latest.target_path} · ${fmtTime(latest.started_at ?? latest.created_at)}` })),
    incompleteBanner(latest),
    busy ? h("div", { class: "banner info", text: "This scan is still running. Open it to follow progress." }) : null,
    h("div", { class: "grid grid-3 section" }, riskCard(latest.summary), categoryCards(latest.summary)),
    h("div", { class: "grid grid-2 section" },
      h("div", { class: "card" }, h("h3", { text: "Severity distribution" }), severityBar(latest.summary.by_severity)),
      h("div", { class: "card" }, h("h3", { text: `Risk score trend — ${baseName(latest.target_path)}` }), trendChart(sameTarget))),
    h("section", { class: "section" }, h("div", { class: "row" }, h("h2", { text: "Recent scans" }), h("a", { class: "small", href: "#/history", text: "View all" })),
      table(SCAN_HEADERS, scans.items.slice(0, 5).map(scanRow))));
}
