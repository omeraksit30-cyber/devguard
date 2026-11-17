import { api } from "../api.js";
import {
  CATEGORIES, CATEGORY_LABEL, SCANNER_LABEL, errorBox, fmtTime, h, incompleteBadge, loading, mount,
  riskLevelLabel, riskText, safeLink, severityBadge, statusBadge, statusLabel, table,
} from "../dom.js";

export function riskCard(summary) {
  const r = summary.risk;
  return h("div", { class: "card" },
    h("div", { class: "stat-label", text: "Risk score" }),
    h("div", { class: "row" },
      h("span", { class: "stat", text: riskText(r.score, r.incomplete) }),
      h("span", { class: "badge st-neutral", text: "Level: " + riskLevelLabel(r.level) })),
    incompleteBadge(r) ? h("p", {}, incompleteBadge(r)) : null,
    r.incomplete ? h("p", { class: "small muted", text: r.score > 0
      ? "Lower bound: scanners that did not run are not counted."
      : "No score available: the scanners that did not run could not report findings." }) : null,
    h("p", { class: "small muted", text: "Heuristic indicator, not a CVSS score." }));
}

// A number is shown only when the scanner succeeded. Otherwise: status badge + reason, never "0".
export function categoryCards(summary) {
  return CATEGORIES.map((c) => {
    const e = summary.by_category[c];
    const ok = e.status === "success";
    return h("div", { class: "card" },
      h("div", { class: "stat-label", text: CATEGORY_LABEL[c] }),
      ok ? h("div", { class: "stat", text: String(e.count) }) : h("p", {}, statusBadge(e.status)),
      h("p", { class: "small muted", text: ok ? (e.count === 1 ? "finding" : "findings")
        : (e.reason || (e.status === "pending" || e.status === "running" ? "Scanner has not finished yet." : "Result unknown — not clean.")) }));
  });
}

export function incompleteBanner(scan) {
  if (scan.status !== "partial" && scan.status !== "failed") return null;
  const n = scan.summary.risk.scanners_not_run;
  return h("div", { class: "banner", role: "alert",
    text: `This scan is incomplete. ${n} scanner(s) did not run. Missing categories are unknown, not clean.` });
}

export function findingsTable(items, { onOpen, group = false, emptyText = "No findings match." } = {}) {
  if (!items.length) return h("div", { class: "table-wrap" }, h("p", { class: "state", text: emptyText }));
  const row = (f) => h("tr", { class: f.triage_status === "false_positive" ? "fp" : null },
    h("td", {}, severityBadge(f.severity)),
    h("td", { text: CATEGORY_LABEL[f.category] ?? f.category }),
    h("td", { class: "mono", text: f.rule_or_vulnerability_id }),
    h("td", { class: "wrap" }, onOpen
      ? h("button", { class: "linklike", type: "button", onclick: () => onOpen(f), text: f.title })
      : h("a", { href: `#/findings/${f.id}`, text: f.title })),
    h("td", { class: "wrap mono", text: f.affected_target }),
    h("td", {}, statusBadge(f.triage_status ?? "open")),
    h("td", { class: "small", text: fmtTime(f.first_seen) }));
  let rows;
  if (group) {
    rows = CATEGORIES.flatMap((c) => {
      const part = items.filter((f) => f.category === c);
      return part.length ? [h("tr", { class: "group-row" }, h("td", { colspan: 7, text: `${CATEGORY_LABEL[c]} (${part.length})` })), ...part.map(row)] : [];
    });
  } else rows = items.map(row);
  return table(["Severity", "Category", "ID", "Title", "Affected target", "Triage", "First seen"], rows);
}

// Finding detail body, used by both the drawer and the standalone page.
export function findingDetail(id, onChanged) {
  const box = h("div", {}, loading());
  const load = async () => {
    try {
      const f = await api.get(`/findings/${id}`);
      mount(box, render(f));
    } catch (err) { mount(box, errorBox(err, load)); }
  };

  function render(f) {
    const kv = (k, v) => (v === null || v === undefined || v === "" ? [] : [h("dt", { text: k }), h("dd", {}, v)]);
    const status = h("select", { id: "triage-status" }, ["open", "acknowledged", "false_positive"].map((v) =>
      h("option", { value: v, selected: f.triage.status === v, text: statusLabel(v) })));
    const note = h("textarea", { id: "triage-note", maxlength: 1000, value: f.triage.note ?? "" });
    const msg = h("span", { class: "small", role: "status" });
    const save = h("button", { class: "btn primary", type: "submit", text: "Save" });
    const form = h("form", { class: "card", onsubmit: async (ev) => {
      ev.preventDefault();
      save.disabled = true; msg.textContent = "Saving…"; msg.className = "small muted";
      try {
        await api.put(`/findings/${id}/triage`, { status: status.value, note: note.value });
        msg.textContent = "Saved."; msg.className = "small pass";
        onChanged?.();
      } catch (err) { msg.textContent = err.message; msg.className = "small fail"; }
      save.disabled = false;
    } },
      h("h3", { text: "Triage" }),
      h("div", { class: "field" }, h("label", { for: "triage-status", text: "Status" }), status),
      h("div", { class: "field" }, h("label", { for: "triage-note" }, "Note ", h("span", { class: "hint", text: "(plain text, up to 1000 characters)" })), note),
      h("div", { class: "row" }, save, msg),
      h("p", { class: "small muted", text: "Triage applies to this finding in every scan of the same target. False positives are hidden by default and excluded from the risk score." }));

    const fp = h("span", { class: "mono", title: f.fingerprint, text: f.fingerprint.slice(0, 16) + "…" });
    const copy = h("button", { class: "btn small", type: "button", text: "Copy", onclick: async () => {
      try { await navigator.clipboard.writeText(f.fingerprint); copy.textContent = "Copied"; } catch { copy.textContent = "Copy failed"; }
    } });
    const location = f.file_path ? f.file_path + (f.line_start ? `:${f.line_start}${f.line_end && f.line_end !== f.line_start ? "–" + f.line_end : ""}` : "") : null;

    return [
      h("div", { class: "row" }, severityBadge(f.severity), statusBadge(f.triage.status),
        h("span", { class: "badge st-neutral", text: CATEGORY_LABEL[f.category] ?? f.category })),
      h("h2", { class: "section", text: f.title }),
      f.category === "secret"
        ? h("div", { class: "banner info", text: "Value redacted — DevGuard never stores or displays matched secrets." }) : null,
      h("div", { class: "remediation" }, h("h3", { text: "Remediation" }), h("div", { class: "pre", text: f.remediation })),
      h("dl", { class: "kv" },
        kv("ID", h("span", { class: "mono", text: f.rule_or_vulnerability_id })),
        kv("Affected target", h("span", { class: "mono", text: f.affected_target })),
        kv("File", location && h("span", { class: "mono", text: location })),
        kv("Resource", f.resource),
        kv("Package", f.package_name),
        kv("Installed version", f.installed_version && h("span", { class: "mono", text: f.installed_version })),
        kv("Fixed version", f.category === "dependency" ? h("span", { class: "mono", text: f.fixed_version ?? "none published" }) : null),
        kv("Original rating", f.category === "secret"
          ? "Gitleaks does not assign severity; DevGuard treats potential secrets as High."
          : (f.original_severity ?? "not provided")),
        kv("Scanner", `${SCANNER_LABEL[f.scanner] ?? f.scanner}${f.scanner_version ? " " + f.scanner_version : ""}`),
        kv("Occurrences", f.occurrences > 1 ? String(f.occurrences) : null),
        kv("Reference", f.reference_url ? safeLink(f.reference_url) : null),
        kv("Fingerprint", h("span", { class: "row" }, fp, copy)),
        kv("First seen", fmtTime(f.first_seen)),
        kv("Seen in scans", h("span", {}, f.seen_in_scans.flatMap((sid, i) => [i ? ", " : "", h("a", { href: `#/scans/${sid}`, text: `#${sid}` })])))),
      f.description ? h("div", { class: "section" }, h("h3", { text: "Description" }), h("div", { class: "pre", text: f.description })) : null,
      h("div", { class: "section" }, form),
    ];
  }
  load();
  return box;
}

let activeDrawerClose = null;

export function openFindingDrawer(id, onChanged) {
  activeDrawerClose?.();
  const previous = document.activeElement;
  const outside = [...document.querySelectorAll("body > header, body > main, body > footer")];
  outside.forEach((el) => { el.inert = true; });
  const close = () => {
    activeDrawerClose = null;
    outside.forEach((el) => { el.inert = false; });
    backdrop.remove();
    drawer.remove();
    document.removeEventListener("keydown", onKey);
    window.removeEventListener("hashchange", close);
    if (previous?.isConnected) previous.focus?.();
  };
  activeDrawerClose = close;
  const onKey = (ev) => { if (ev.key === "Escape") close(); };
  const backdrop = h("div", { class: "drawer-backdrop", onclick: close });
  const closeBtn = h("button", { class: "btn small", type: "button", onclick: close, text: "Close" });
  const drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": "Finding detail" },
    h("div", { class: "drawer-head" }, h("a", { class: "small", href: `#/findings/${id}`, onclick: close, text: "Open as page" }), closeBtn),
    findingDetail(id, onChanged));
  document.body.append(backdrop, drawer);
  document.addEventListener("keydown", onKey);
  window.addEventListener("hashchange", close, { once: true });
  closeBtn.focus();
  return close;
}
