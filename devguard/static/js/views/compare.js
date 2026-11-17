import { api, qs } from "../api.js";
import { CATEGORY_LABEL, baseName, empty, errorBox, fmtTime, h, isIncomplete, loading, mount, riskText, statusBadge, statusLabel } from "../dom.js";
import { navigate } from "../router.js";
import { findingsTable, openFindingDrawer } from "./components.js";

export async function compare(root, ctx) {
  const list = (await api.get("/scans" + qs({ limit: 200 }))).items.filter((s) => ["completed", "partial"].includes(s.status));
  const head = h("div", { class: "page-head" }, h("div", {}, h("h1", { text: "Compare scans" }),
    h("p", { class: "sub", text: "See which findings are new, resolved or persistent between two scans." })));
  if (list.length < 2) {
    mount(root, head, h("div", { class: "card" }, empty("Not enough scans", "Two completed or partial scans are needed for a comparison.",
      h("a", { class: "btn primary", href: "#/scans/new", text: "New scan" }))));
    return;
  }
  // Default: the two most recent *completed* scans of one target, so the overall risk difference is
  // meaningful. Falls back to the two most recent comparable scans when no target has two completed ones.
  const done = list.filter((s) => s.status === "completed");
  const pairTarget = done.find((s) => done.filter((x) => x.target_path === s.target_path).length >= 2)?.target_path;
  const pair = pairTarget ? done.filter((s) => s.target_path === pairTarget)
    : list.filter((s) => s.target_path === list[0].target_path).concat(list).slice(0, 2);
  let base = Number(ctx.query.get("base")) || pair[1].id;
  let headId = Number(ctx.query.get("head")) || pair[0].id;

  const option = (s, sel) => h("option", { value: s.id, selected: s.id === sel,
    text: `#${s.id} · ${baseName(s.target_path)} · ${fmtTime(s.started_at)}${s.label ? " · " + s.label : ""}${s.status === "partial" ? " · partial" : ""}` });
  const go = () => navigate(`/compare${qs({ base: baseSel.value, head: headSel.value })}`);
  const baseSel = h("select", { id: "base", onchange: go }, list.map((s) => option(s, base)));
  const headSel = h("select", { id: "head", onchange: go }, list.map((s) => option(s, headId)));
  const pickers = h("div", { class: "card grid grid-2" },
    h("div", { class: "field" }, h("label", { for: "base", text: "Base (older)" }), baseSel),
    h("div", { class: "field" }, h("label", { for: "head", text: "Head (newer)" }), headSel));
  const out = h("div", { class: "section" }, loading());
  mount(root, head, pickers, out);

  if (base === headId) { mount(out, h("div", { class: "banner info", text: "Choose two different scans to compare." })); return; }
  let r;
  try { r = await api.get("/compare" + qs({ base, head: headId })); } catch (err) { mount(out, errorBox(err)); return; }

  const d = r.risk.delta;
  const incompleteScans = [r.base, r.head].filter(isIncomplete);
  const stat = (label, value, cls) => h("div", { class: "card" }, h("div", { class: "stat-label", text: label }), h("div", { class: "stat " + (cls || ""), text: String(value) }));
  let active = ctx.query.get("tab") || "new";
  const tabBox = h("div", {});
  const tabs = h("div", { class: "tabs", role: "tablist", "aria-label": "Comparison result categories" });
  const renderTabs = () => {
    mount(tabs, ["new", "resolved", "persistent"].map((k) => h("button", { class: "tab", type: "button", role: "tab", "aria-selected": String(active === k),
      onclick: () => { active = k; renderTabs(); } }, k.charAt(0).toUpperCase() + k.slice(1), h("span", { class: "count", text: String(r.totals[k]) }))));
    mount(tabBox, findingsTable(r[active], { group: true, onOpen: (f) => openFindingDrawer(f.id),
      emptyText: `No ${active} findings in the comparable categories.` }));
  };
  renderTabs();

  mount(out,
    r.targets_differ ? h("div", { class: "banner", role: "alert", text: "These scans have different targets. Findings are matched by relative path, so results are meaningful only if the two directories hold versions of the same project." }) : null,
    !r.fully_comparable ? h("div", { class: "banner", role: "alert", text: "Some categories could not be compared. Their findings are excluded from all three lists — missing data is not counted as resolved." }) : null,
    h("div", { class: "grid grid-3" },
      stat("New", r.totals.new, r.totals.new ? "delta-up" : ""), stat("Resolved", r.totals.resolved, r.totals.resolved ? "delta-down" : ""),
      stat("Persistent", r.totals.persistent),
      h("div", { class: "card" }, h("div", { class: "stat-label", text: "Risk score" }),
        h("div", { class: "stat", text: `${riskText(r.risk.base, isIncomplete(r.base))} → ${riskText(r.risk.head, isIncomplete(r.head))}` }),
        // A score from an incomplete scan only counts the scanners that ran, so a drop is not an improvement.
        incompleteScans.length ? h("p", { class: "delta-na", text: `Not directly comparable — ${incompleteScans.map((s) => `scan #${s.id} is incomplete (${statusLabel(s.status).toLowerCase()})`).join(", ")}.` })
        : d === null ? null : h("p", { class: d > 0 ? "delta-up" : d < 0 ? "delta-down" : "muted", text: d > 0 ? `+${d} (higher)` : d < 0 ? `${d} (lower)` : "No change" }),
        h("p", { class: "small muted", text: "Heuristic indicator, not a CVSS score." }))),
    h("section", { class: "section" }, h("h2", { text: "By category" }), h("div", { class: "grid grid-3" }, r.categories.map((c) =>
      h("div", { class: "card" }, h("h3", { text: CATEGORY_LABEL[c.category] }),
        c.comparable ? h("p", {}, `New ${c.new} · Resolved ${c.resolved} · Persistent ${c.persistent}`)
          : h("div", { class: "notcomp", text: `Not comparable — ${c.reason}` }))))),
    h("section", { class: "section" }, h("div", { class: "row" }, h("h2", { text: "Findings" }),
      h("span", { class: "small muted" }, "Base ", h("a", { href: `#/scans/${r.base.id}`, text: `#${r.base.id}` }), " ", statusBadge(r.base.status),
        " → Head ", h("a", { href: `#/scans/${r.head.id}`, text: `#${r.head.id}` }), " ", statusBadge(r.head.status))), tabs, tabBox));
}
