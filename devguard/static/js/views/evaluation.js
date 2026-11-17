import { api } from "../api.js";
import { CATEGORIES, CATEGORY_LABEL, errorBox, fmtDuration, fmtTime, h, isIncomplete, mount, riskText, statusBadge, statusLabel, table } from "../dom.js";

function results(run) {
  const res = run.results;
  if (run.status === "running") return h("div", { class: "card" }, h("p", { class: "state", role: "status" }, h("span", { class: "spinner", "aria-hidden": "true" }),
    "Scanning both fixtures (three scans). This usually takes under a minute…"));
  if (!res) return null;
  if (res.error) return h("div", { class: "banner error", role: "alert", text: res.error });
  const cell = (s, c) => (s.by_category[c].count !== null ? String(s.by_category[c].count) : statusLabel(s.by_category[c].status));
  const comp = res.comparison;
  return [
    h("section", { class: "section" }, h("h2", { text: "Acceptance criteria" }),
      table(["#", "Criterion", "Result", "Evidence"], res.checks.map((c) => h("tr", {},
        h("td", { class: "mono", text: c.id }), h("td", { text: c.name }),
        h("td", {}, h("span", { class: c.passed ? "pass" : "fail", text: c.passed ? "PASS" : "FAIL" })),
        h("td", { class: "wrap", text: c.evidence }))))),
    h("div", { class: "grid grid-2 section" },
      h("div", {}, h("h2", { text: "Environment" }), table(["Item", "Value"], Object.entries(res.environment).map(([k, v]) =>
        h("tr", {}, h("td", { text: { os: "Operating system", python: "Python", trivy: "Trivy", gitleaks: "Gitleaks" }[k] ?? k }), h("td", { class: "mono wrap", text: v ?? "not recorded" }))))),
      h("div", {}, h("h2", { text: "Fixture scans" }), table(["Scan", "Status", "Duration", ...CATEGORIES.map((c) => CATEGORY_LABEL[c]), "Risk"],
        Object.entries(res.scans).map(([name, s]) => h("tr", {},
          h("td", {}, h("a", { href: `#/scans/${s.id}`, text: `#${s.id} ${name.replace("_", " ")}` })), h("td", {}, statusBadge(s.status)),
          h("td", { class: "num", text: fmtDuration(s.elapsed_ms) }), CATEGORIES.map((c) => h("td", { class: "num", text: cell(s, c) })),
          h("td", { class: "num", text: riskText(s.risk_score, isIncomplete(s)) })))))),
    comp ? h("section", { class: "section" }, h("h2", { text: "Comparison: vulnerable-app → fixed-app" }),
      table(["Category", "New", "Resolved", "Persistent"], comp.categories.map((c) => h("tr", {},
        h("td", { text: CATEGORY_LABEL[c.category] }),
        c.comparable ? [h("td", { class: "num", text: String(c.new) }), h("td", { class: "num", text: String(c.resolved) }), h("td", { class: "num", text: String(c.persistent) })]
          : h("td", { colspan: 3, class: "muted", text: `Not comparable — ${c.reason}` })))),
      h("p", { class: "small muted", text: `Risk score ${comp.risk.base} → ${comp.risk.head}. Heuristic indicator, not a CVSS score.` }),
      h("p", {}, h("a", { href: `#/compare?base=${res.scans.vulnerable.id}&head=${res.scans.fixed.id}`, text: "Open full comparison" }))) : null,
  ];
}

export async function evaluation(root, ctx) {
  let runs = (await api.get("/evaluation/runs")).items;
  let current = runs[0] ?? null;
  let timer = null;
  const body = h("div", {});
  const actions = h("div", { class: "row" });
  const error = h("div", { role: "alert" });

  function render() {
    const running = current?.status === "running";
    const runBtn = h("button", { class: "btn primary", type: "button", disabled: running, text: running ? "Running…" : "Run evaluation", onclick: async () => {
      mount(error);
      try { current = await api.post("/evaluation/run"); render(); schedule(); } catch (err) { mount(error, h("div", { class: "banner error", text: err.message })); }
    } });
    const picker = runs.length > 1 ? h("select", { "aria-label": "Past evaluation runs", onchange: async (ev) => {
      current = await api.get(`/evaluation/runs/${ev.target.value}`); render();
    } }, runs.map((r) => h("option", { value: r.id, selected: r.id === current?.id, text: `Run #${r.id} · ${fmtTime(r.created_at)} · ${statusLabel(r.status)}` }))) : null;
    const exportBtn = current && !running && current.results && !current.results.error
      ? h("a", { class: "btn", href: `/api/evaluation/runs/${current.id}/export`, download: "", text: "Export evidence (Markdown)" }) : null;
    mount(actions, picker, exportBtn, runBtn);
    mount(body, current
      ? [h("div", { class: "row" }, h("h2", { text: `Run #${current.id}` }), statusBadge(current.status), h("span", { class: "muted small", text: fmtTime(current.created_at) })), results(current)]
      : h("div", { class: "card" }, h("p", { class: "state" }, h("strong", { text: "No evaluation runs yet" }),
        "Run the evaluation to scan the bundled vulnerable-app and fixed-app fixtures and check the four acceptance criteria.")));
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!ctx.alive() || !current) return;
      try {
        current = await api.get(`/evaluation/runs/${current.id}`);
        if (current.status === "running") schedule(); else runs = (await api.get("/evaluation/runs")).items;
        render();
      } catch (err) { mount(body, errorBox(err)); }
    }, 1000);
  }

  mount(root, h("div", { class: "page-head" }, h("div", {}, h("h1", { text: "Evaluation" }),
    h("p", { class: "sub", text: "Reproducible check of DevGuard against its bundled fixtures." })), actions), error, body);
  render();
  if (current?.status === "running") schedule();
  return () => clearTimeout(timer);
}
