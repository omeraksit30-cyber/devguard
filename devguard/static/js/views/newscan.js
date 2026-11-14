import { api } from "../api.js";
import { baseName, h, mount } from "../dom.js";
import { navigate } from "../router.js";

export async function newScan(root) {
  const cfg = await api.get("/system/config");
  const dirs = cfg.allowed_roots.flatMap((r) => r.directories);
  const path = h("input", { type: "text", id: "target", required: true, autocomplete: "off", spellcheck: "false", value: dirs[0] ?? "" });
  const picker = h("select", { id: "picker", onchange: (ev) => { if (ev.target.value) path.value = ev.target.value; } },
    h("option", { value: "", text: dirs.length ? "Choose a directory…" : "No directories found under the allowed roots" }),
    dirs.map((d, i) => h("option", { value: d, selected: i === 0, text: `${baseName(d)} — ${d}` })));
  const label = h("input", { type: "text", id: "label", maxlength: 200, placeholder: "e.g. before upgrade" });
  const confirm = h("input", { type: "checkbox", id: "confirm", required: true });
  const error = h("div", { role: "alert" });
  const submit = h("button", { class: "btn primary", type: "submit", text: "Start scan" });

  const form = h("form", { class: "card", onsubmit: async (ev) => {
    ev.preventDefault();
    if (!confirm.checked) return;
    submit.disabled = true; submit.textContent = "Starting…"; mount(error);
    try {
      const scan = await api.post("/scans", { target_path: path.value.trim(), label: label.value.trim() || null });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      mount(error, h("div", { class: "banner error", text: err.message }));
      submit.disabled = false; submit.textContent = "Start scan";
    }
  } },
    error,
    h("div", { class: "field" }, h("label", { for: "picker", text: "Target directory" }), picker),
    h("div", { class: "field" }, h("label", { for: "target" }, "Path ", h("span", { class: "hint", text: "(pick above or type a path inside an allowed root)" })), path),
    h("div", { class: "field" }, h("label", { for: "label" }, "Label ", h("span", { class: "hint", text: "(optional)" })), label),
    h("div", { class: "field" }, h("label", { class: "check", for: "confirm" }, confirm, "I confirm I am authorized to scan this directory.")),
    h("div", { class: "row" }, submit, h("a", { class: "btn", href: "#/", text: "Cancel" })));

  mount(root,
    h("div", { class: "page-head" }, h("div", {}, h("h1", { text: "New scan" }),
      h("p", { class: "sub", text: "Runs dependency, secret and configuration scanners on a local directory." }))),
    form,
    h("div", { class: "card section" }, h("h3", { text: "Allowed roots" }),
      h("p", { class: "small muted", text: "Only directories under these roots can be scanned. Change them in devguard.toml." }),
      h("ul", {}, cfg.allowed_roots.map((r) => h("li", { class: "mono", text: r.path + (r.exists ? "" : " (missing)") })))));
}
