// Hash router: #/path?query. A view is (root, ctx) => optional cleanup function.
import { errorBox, loading, mount } from "./dom.js";

const routes = [];
let cleanup = null;
let generation = 0;

export const route = (pattern, view, nav) => routes.push({ pattern, view, nav });

export function parseHash() {
  const raw = location.hash.replace(/^#/, "") || "/";
  const [path, query = ""] = raw.split("?");
  return { path: path || "/", query: new URLSearchParams(query) };
}

export function navigate(path) {
  if (location.hash === "#" + path) render(); else location.hash = path;
}

// Update the query string without re-rendering (used for filter state).
export function setQuery(params) {
  const { path } = parseHash();
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== "" && v !== null && v !== undefined && v !== false) sp.set(k, v === true ? "1" : v);
  const q = sp.toString();
  history.replaceState(null, "", "#" + path + (q ? "?" + q : ""));
}

async function render() {
  const root = document.getElementById("app");
  const mine = ++generation;
  if (cleanup) { try { cleanup(); } catch { /* ignore */ } cleanup = null; }
  const { path, query } = parseHash();
  const match = routes.map((r) => ({ r, m: path.match(r.pattern) })).find((x) => x.m);
  document.querySelectorAll("[data-nav]").forEach((a) => {
    if (match && a.dataset.nav === match.r.nav) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  if (!match) {
    mount(root, errorBox({ message: "This page does not exist." }));
    return;
  }
  mount(root, loading());
  const ctx = { params: match.m.slice(1), query, alive: () => mine === generation, reload: render };
  try {
    const result = await match.r.view(root, ctx);
    if (mine !== generation) { if (typeof result === "function") result(); return; }
    if (typeof result === "function") cleanup = result;
  } catch (err) {
    if (mine === generation) mount(root, errorBox(err, render));
  }
}

export function start() {
  window.addEventListener("hashchange", render);
  render();
}
