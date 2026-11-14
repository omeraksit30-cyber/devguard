// Thin fetch wrapper. All requests are same-origin; nothing leaves 127.0.0.1.
export class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

async function request(method, path, body) {
  const opts = { method, headers: { Accept: "application/json" }, credentials: "omit", cache: "no-store" };
  if (method !== "GET") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body ?? {});
  }
  let res;
  try {
    res = await fetch("/api" + path, opts);
  } catch {
    throw new ApiError(0, "network", "Cannot reach the DevGuard server. Is it still running?");
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON body */ }
  if (!res.ok) {
    throw new ApiError(res.status, data?.error ?? "error", data?.message ?? `Request failed (${res.status})`);
  }
  return data;
}

export const api = {
  get: (path) => request("GET", path),
  post: (path, body) => request("POST", path, body),
  put: (path, body) => request("PUT", path, body),
  del: (path) => request("DELETE", path),
};

export function qs(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
    else if (v !== null && v !== undefined && v !== "") sp.set(k, v);
  }
  const s = sp.toString();
  return s ? "?" + s : "";
}
