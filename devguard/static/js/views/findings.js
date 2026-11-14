// Filterable findings panel embedded in the scan detail page. Filter state lives in the URL hash.
import { api, qs } from "../api.js";
import { CATEGORIES, CATEGORY_LABEL, SEVERITIES, errorBox, h, loading, mount, statusBadge } from "../dom.js";
import { setQuery } from "../router.js";
import { findingsTable, openFindingDrawer } from "./components.js";

export function findingsPanel(scan, query, onTriageChanged) {
  const state = {
    category: CATEGORIES.includes(query.get("category")) ? query.get("category") : "",
    severity: (query.get("severity") || "").split(",").filter((x) => SEVERITIES.includes(x)),
    triage: ["open", "acknowledged", "false_positive"].includes(query.get("triage")) ? query.get("triage") : "",
    fp: query.get("fp") === "1",
    q: query.get("q") || "",
    group: query.get("group") === "1",
  };
  const body = h("div", {}, loading());
  const tabs = h("div", { class: "tabs", role: "tablist", "aria-label": "Category" });
  let seq = 0;

  async function refresh() {
    if (seq > 0 && !body.isConnected) return;
    setQuery({ category: state.category, severity: state.severity.join(","), triage: state.triage, fp: state.fp, q: state.q, group: state.group });
    renderTabs();
    const mine = ++seq;
    try {
      const data = await api.get(`/scans/${scan.id}/findings` + qs({
        category: state.category, severity: state.severity, q: state.q,
        triage: state.triage || (state.fp ? "all" : ""), sort: state.group ? "category" : "severity",
      }));
      if (mine !== seq) return;
      const cat = state.category && scan.summary.by_category[state.category];
      const unknown = cat && cat.status !== "success";
      mount(body,
        h("p", { class: "small muted", role: "status", text: `${data.total} finding(s) shown` }),
        findingsTable(data.items, {
          group: state.group,
          onOpen: (f) => openFindingDrawer(f.id, () => { onTriageChanged?.(); refresh(); }),
          emptyText: unknown ? "This scanner did not complete, so results for this category are unknown — not clean."
            : "No findings match the current filters.",
        }));
    } catch (err) { if (mine === seq) mount(body, errorBox(err, refresh)); }
  }

  function renderTabs() {
    const tab = (value, label, extra) => h("button", { class: "tab", type: "button", role: "tab", "aria-selected": String(state.category === value),
      onclick: () => { state.category = value; refresh(); } }, label, extra);
    mount(tabs, tab("", "All", h("span", { class: "count", text: String(scan.summary.total) })),
      CATEGORIES.map((c) => {
        const e = scan.summary.by_category[c];
        return tab(c, CATEGORY_LABEL[c], e.status === "success" ? h("span", { class: "count", text: String(e.count) }) : statusBadge(e.status));
      }));
  }

  let timer;
  const search = h("input", { type: "search", placeholder: "Search title, ID or target", "aria-label": "Search findings", value: state.q,
    oninput: (ev) => { clearTimeout(timer); timer = setTimeout(() => { state.q = ev.target.value.trim(); refresh(); }, 250); } });
  const sevBoxes = h("fieldset", {}, h("legend", { text: "Severity" }), SEVERITIES.map((sv) =>
    h("label", {}, h("input", { type: "checkbox", checked: state.severity.includes(sv), onchange: (ev) => {
      state.severity = ev.target.checked ? [...state.severity, sv] : state.severity.filter((x) => x !== sv); refresh();
    } }), sv.charAt(0).toUpperCase() + sv.slice(1))));
  const triage = h("select", { "aria-label": "Triage status", onchange: (ev) => { state.triage = ev.target.value; refresh(); } },
    [["", "Any triage status"], ["open", "Open"], ["acknowledged", "Acknowledged"], ["false_positive", "False positive"]]
      .map(([v, t]) => h("option", { value: v, selected: state.triage === v, text: t })));
  const toggle = (label, key) => h("label", {}, h("input", { type: "checkbox", checked: state[key],
    onchange: (ev) => { state[key] = ev.target.checked; refresh(); } }), label);

  refresh();
  return h("section", { class: "section", "aria-label": "Findings" },
    h("h2", { text: "Findings" }), tabs,
    h("div", { class: "filters" }, search, sevBoxes, triage, toggle("Show false positives", "fp"), toggle("Group by category", "group")),
    body);
}
