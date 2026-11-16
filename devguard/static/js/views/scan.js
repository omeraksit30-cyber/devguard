import { api, qs } from "../api.js";
import { severityBar } from "../charts.js";
import { SCANNER_LABEL, baseName, fmtDuration, fmtTime, h, mount, statusBadge, table } from "../dom.js";
import { navigate } from "../router.js";
import { categoryCards, findingDetail, incompleteBanner, riskCard } from "./components.js";
import { findingsPanel } from "./findings.js";

const busy = (s) => s.status === "queued" || s.status === "running";

function progressPanel(scan) {
  return table(["Scanner", "Status", "Version", "Duration", "Result"], scan.scanner_runs.map((r) => h("tr", {},
    h("td", { text: SCANNER_LABEL[r.scanner] ?? r.scanner }),
    h("td", {}, statusBadge(r.status)),
    h("td", { class: "mono", text: r.tool_version ?? "—" }),
    h("td", { class: "num", text: fmtDuration(r.elapsed_ms) }),
    h("td", { class: "wrap" }, r.status === "success" ? `${r.findings_count} finding(s)`
      : (r.skip_reason || r.error_message || (r.status === "pending" || r.status === "running" ? "…" : "Result unknown"))))));
}

export async function scanDetail(root, ctx) {
  const id = ctx.params[0];
  let scan = await api.get(`/scans/${id}`);
  let timer = null;
  const top = h("div", {});
  const summaryBox = h("div", {});
  const findingsBox = h("div", {});

  async function refreshSummary() {
    scan = await api.get(`/scans/${id}`);
    renderTop();
  }

  function renderTop() {
    const others = h("select", { "aria-label": "Compare with another scan of this target", onchange: (ev) => {
      if (ev.target.value) navigate(`/compare${qs({ base: ev.target.value, head: id })}`);
    } }, h("option", { value: "", text: "Compare with…" }));
    if (!busy(scan)) api.get("/scans" + qs({ target_path: scan.target_path, limit: 50 })).then((list) => {
      list.items.filter((s) => s.id !== scan.id && ["completed", "partial"].includes(s.status))
        .forEach((s) => others.append(h("option", { value: s.id, text: `#${s.id} · ${fmtTime(s.started_at)}${s.label ? " · " + s.label : ""}` })));
    }).catch(() => {});
    const del = h("button", { class: "btn danger", type: "button", disabled: scan.status === "running", text: "Delete", onclick: async () => {
      if (!window.confirm(`Delete scan #${scan.id} and all of its findings? This cannot be undone.`)) return;
      try { await api.del(`/scans/${scan.id}`); navigate("/history"); } catch (err) { window.alert(err.message); }
    } });
    const exports = busy(scan) ? null : h("span", { class: "row" }, h("span", { class: "muted small", text: "Export:" }),
      ["json", "md", "html"].map((f) => h("a", { class: "btn small", href: `/api/scans/${scan.id}/export?format=${f}`, download: "",
        text: { json: "JSON", md: "Markdown", html: "HTML" }[f] })));
    mount(top,
      h("div", { class: "page-head" },
        h("div", {}, h("div", { class: "row" }, h("h1", { text: `Scan #${scan.id} — ${baseName(scan.target_path)}` }), statusBadge(scan.status)),
          h("p", { class: "sub mono", text: scan.target_path }),
          h("p", { class: "sub small", text: [scan.label ? `Label: ${scan.label}` : null, `Started ${fmtTime(scan.started_at ?? scan.created_at)}`,
            `Duration ${fmtDuration(scan.elapsed_ms)}`].filter(Boolean).join(" · ") })),
        h("div", { class: "row" }, exports, busy(scan) ? null : others, del)),
      incompleteBanner(scan),
      h("section", {}, h("h2", { text: busy(scan) ? "Progress" : "Scanners" }), progressPanel(scan)));
    mount(summaryBox, busy(scan) ? null : [
      h("div", { class: "grid grid-3 section" }, riskCard(scan.summary), categoryCards(scan.summary)),
      h("div", { class: "card section" }, h("h3", { text: "Severity distribution" }), severityBar(scan.summary.by_severity))]);
  }

  function showFindings() { mount(findingsBox, findingsPanel(scan, ctx.query, () => refreshSummary().catch(() => {}))); }

  async function poll() {
    if (!ctx.alive()) return;
    try {
      scan = await api.get(`/scans/${id}`);
      if (!ctx.alive()) return;
      renderTop();
      if (busy(scan)) timer = setTimeout(poll, 1000); else showFindings();
    } catch { timer = setTimeout(poll, 2000); }
  }

  mount(root, top, summaryBox, findingsBox);
  renderTop();
  if (busy(scan)) timer = setTimeout(poll, 1000); else showFindings();
  return () => clearTimeout(timer);
}

export async function findingPage(root, ctx) {
  const f = await api.get(`/findings/${ctx.params[0]}`);
  mount(root,
    h("div", { class: "page-head" }, h("div", {}, h("h1", { text: "Finding detail" }),
      h("p", { class: "sub" }, h("a", { href: `#/scans/${f.scan_id}`, text: `← Back to scan #${f.scan_id}` })))),
    h("div", { class: "card" }, findingDetail(f.id)));
}
