// Hand-drawn inline SVG charts. Colours come from CSS classes (CSP forbids inline styles).
import { h, s, SEVERITIES } from "./dom.js";

const cap = (x) => x.charAt(0).toUpperCase() + x.slice(1);

export function severityBar(bySeverity) {
  const total = SEVERITIES.reduce((n, k) => n + (bySeverity[k] || 0), 0);
  const W = 600, H = 26;
  const summary = SEVERITIES.map((k) => `${cap(k)} ${bySeverity[k] || 0}`).join(", ");
  const svg = s("svg", { class: "chart bar", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Severity distribution: ${summary}`,
    preserveAspectRatio: "none" });
  if (total === 0) {
    svg.append(s("rect", { x: 0, y: 0, width: W, height: H, rx: 6, class: "fill-empty" }));
  } else {
    let x = 0;
    for (const k of SEVERITIES) {
      const n = bySeverity[k] || 0;
      if (!n) continue;
      const w = (n / total) * W;
      svg.append(s("rect", { x, y: 0, width: Math.max(w - 2, 1), height: H, rx: 4, class: "fill-" + k }, s("title", {}, `${cap(k)}: ${n}`)));
      x += w;
    }
  }
  const legend = h("div", { class: "legend" }, SEVERITIES.map((k) =>
    h("span", {}, h("span", { class: "swatch bg-" + k, "aria-hidden": "true" }), `${cap(k)} `, h("strong", { text: String(bySeverity[k] || 0) }))));
  return h("div", {}, svg, legend);
}

// scans: oldest -> newest, each {id, risk_score, status}
export function trendChart(scans) {
  const incompleteScan = (x) => x.incomplete ?? ["partial", "failed"].includes(x.status);
  const scored = scans.filter((x) => x.risk_score !== null && x.risk_score !== undefined);
  // An incomplete scan with a score of 0 has no score to plot; drawing it would look like a drop to "clean".
  const pts = scored.filter((x) => !(incompleteScan(x) && x.risk_score === 0));
  const unplotted = scored.length - pts.length;
  if (pts.length < 2) return h("p", { class: "muted", text: "At least two finished scans of this target are needed to draw a trend." });
  const W = 600, H = 180, L = 36, R = 14, T = 14, B = 26;
  const max = Math.max(10, ...pts.map((p) => p.risk_score));
  const X = (i) => L + (i * (W - L - R)) / (pts.length - 1);
  const Y = (v) => T + (1 - v / max) * (H - T - B);
  // Partial and failed scans are incomplete: their score is not comparable to a full scan,
  // so they are drawn hollow and labelled — a failed scan at 0 must not read as "clean".
  const inc = (p) => p.incomplete ?? ["partial", "failed"].includes(p.status);
  const note = (p) => (inc(p) ? ` (${p.status} scan, incomplete)` : "");
  const label = pts.map((p) => `scan ${p.id}: ${p.risk_score}${note(p)}`).join(", ");
  const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Risk score trend. ${label}` },
    s("line", { class: "axis", x1: L, y1: Y(0), x2: W - R, y2: Y(0) }),
    s("line", { class: "axis", x1: L, y1: T, x2: L, y2: Y(0) }),
    s("text", { x: L - 6, y: Y(0) + 4, "text-anchor": "end" }, "0"),
    s("text", { x: L - 6, y: T + 4, "text-anchor": "end" }, String(max)),
    s("polyline", { class: "line", points: pts.map((p, i) => `${X(i)},${Y(p.risk_score)}`).join(" ") }));
  pts.forEach((p, i) => {
    svg.append(
      s("circle", { class: "dot" + (inc(p) ? " hollow" : ""), cx: X(i), cy: Y(p.risk_score), r: 4.5 },
        s("title", {}, `Scan #${p.id}: ${p.risk_score}${note(p)}`)),
      s("text", { x: X(i), y: H - 8, "text-anchor": "middle" }, `#${p.id}`));
  });
  return h("div", {}, svg,
    h("p", { class: "small muted", text: "Hollow points are partial or failed scans (some scanners did not run); their score is a lower bound." }),
    unplotted ? h("p", { class: "small muted", text: `${unplotted} incomplete scan(s) without a usable score are not plotted.` }) : null);
}
