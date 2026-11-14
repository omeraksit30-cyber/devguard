// DOM helpers. Dynamic text is always inserted with textContent / createTextNode —
// never innerHTML — so scanner output cannot inject markup.
const SVG_NS = "http://www.w3.org/2000/svg";

function build(node, attrs, children) {
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.setAttribute("class", v);
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (k === "value" || k === "checked" || k === "disabled" || k === "selected") node[k] = v;
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export const h = (tag, attrs, ...children) => build(document.createElement(tag), attrs, children);
export const s = (tag, attrs, ...children) => build(document.createElementNS(SVG_NS, tag), attrs, children);
export const clear = (node) => { node.replaceChildren(); return node; };
export const mount = (node, ...children) => { node.replaceChildren(...children.flat(Infinity).filter(Boolean)); return node; };

export const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
export const CATEGORIES = ["dependency", "secret", "config"];
export const CATEGORY_LABEL = { dependency: "Dependencies", secret: "Secrets", config: "Configurations" };
export const SCANNER_LABEL = { "trivy-dependency": "Trivy (dependencies)", gitleaks: "Gitleaks (secrets)", "trivy-config": "Trivy (configuration)" };
const cap = (x) => x.charAt(0).toUpperCase() + x.slice(1);

const STATUS = {
  success: ["Success", "st-ok"], completed: ["Completed", "st-ok"], passed: ["Passed", "st-ok"],
  partial: ["Partial", "st-warn"], skipped: ["Skipped", "st-neutral"], pending: ["Pending", "st-neutral"],
  queued: ["Queued", "st-neutral"], running: ["Running", "st-busy"],
  failed: ["Failed", "st-bad"], timeout: ["Timed out", "st-bad"], not_installed: ["Not installed", "st-bad"], error: ["Error", "st-bad"],
  open: ["Open", "st-neutral"], acknowledged: ["Acknowledged", "st-ok"], false_positive: ["False positive", "st-warn"],
};
export const statusLabel = (st) => (STATUS[st] ?? [cap(String(st))])[0];
export const statusBadge = (st) => h("span", { class: "badge " + (STATUS[st]?.[1] ?? "st-neutral"), text: statusLabel(st) });
export const severityBadge = (sev) => h("span", { class: "badge sev-" + sev, text: cap(sev) });
export const riskLevelLabel = (lvl) => (lvl ? cap(lvl) : "—");

export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
export const fmtDuration = (ms) => (ms === null || ms === undefined ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`);
export const baseName = (p) => (p || "").split("/").filter(Boolean).pop() || p;

export const loading = (text = "Loading…") => h("p", { class: "state", role: "status" }, h("span", { class: "spinner", "aria-hidden": "true" }), text);
export const empty = (title, text, action) => h("div", { class: "state" }, h("strong", { text: title }), text, action ? h("p", {}, action) : null);
export const errorBox = (err, retry) => h("div", { class: "state error", role: "alert" },
  h("strong", { text: "Something went wrong" }), err?.message ?? String(err),
  retry ? h("p", {}, h("button", { class: "btn", onclick: retry, text: "Try again" })) : null);

export function incompleteBadge(risk) {
  return risk?.incomplete ? h("span", { class: "badge st-warn", text: `Incomplete — ${risk.scanners_not_run} scanner(s) did not run` }) : null;
}

export function table(headers, rows, caption) {
  return h("div", { class: "table-wrap" }, h("table", {},
    caption ? h("caption", { class: "small muted", text: caption }) : null,
    h("thead", {}, h("tr", {}, headers.map((x) => typeof x === "string" ? h("th", { scope: "col", text: x }) : x))),
    h("tbody", {}, rows)));
}

// Only https:// links are clickable; anything else is shown as plain text.
export function safeLink(url) {
  if (typeof url === "string" && url.startsWith("https://")) {
    return h("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: url });
  }
  return url ? h("span", { class: "mono", text: url }) : "—";
}
