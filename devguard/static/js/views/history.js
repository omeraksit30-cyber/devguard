import { api, qs } from "../api.js";
import { baseName, empty, h, mount, table } from "../dom.js";
import { navigate } from "../router.js";
import { SCAN_HEADERS, scanRow } from "./dashboard.js";

export async function history(root, ctx) {
  const target = ctx.query.get("target") || "";
  const data = await api.get("/scans" + qs({ target_path: target, limit: 200 }));
  const selected = new Set();
  const compareBtn = h("button", { class: "btn primary", type: "button", disabled: true, text: "Compare selected (0/2)", onclick: () => {
    const [a, b] = [...selected].sort((x, y) => x - y);
    navigate(`/compare${qs({ base: a, head: b })}`);
  } });
  const boxes = [];
  const sync = () => {
    compareBtn.disabled = selected.size !== 2;
    compareBtn.textContent = `Compare selected (${selected.size}/2)`;
    boxes.forEach((b) => { b.disabled = !b.checked && selected.size >= 2; });
  };
  const filter = h("select", { "aria-label": "Filter by target", onchange: (ev) => navigate("/history" + qs({ target: ev.target.value })) },
    h("option", { value: "", text: "All targets" }),
    data.targets.map((t) => h("option", { value: t, selected: t === target, text: `${baseName(t)} — ${t}` })));

  const rows = data.items.map((s) => {
    const ok = ["completed", "partial"].includes(s.status);
    const box = h("input", { type: "checkbox", disabled: !ok, "aria-label": `Select scan ${s.id} for comparison`,
      onchange: (ev) => { if (ev.target.checked) selected.add(s.id); else selected.delete(s.id); sync(); } });
    if (ok) boxes.push(box);
    const tr = scanRow(s);
    tr.prepend(h("td", {}, box));
    return tr;
  });

  mount(root,
    h("div", { class: "page-head" }, h("div", {}, h("h1", { text: "History" }), h("p", { class: "sub", text: "Every scan stored in the local database." })),
      h("div", { class: "row" }, filter, compareBtn)),
    data.items.length ? table([h("th", { scope: "col" }, h("span", { class: "small", text: "Pick 2" })), ...SCAN_HEADERS], rows)
      : h("div", { class: "card" }, empty("No scans found", target ? "No scans exist for this target." : "Start a scan to build history.",
        h("a", { class: "btn primary", href: "#/scans/new", text: "New scan" }))));
}
