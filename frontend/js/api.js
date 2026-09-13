import { preferences } from "./state.js";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function withMask(path) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}mask=${preferences.mask ? "true" : "false"}`;
}

function listParams(query) {
  const params = new URLSearchParams();
  if (query.q) params.set("q", query.q);
  if (query.category) params.set("category", query.category);
  if (query.minRisk) params.set("min_risk", String(query.minRisk));
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset) params.set("offset", String(query.offset));
  return params.toString();
}

async function request(path, init) {
  const response = await fetch(withMask(path), init);
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { error: text };
  }
  if (!response.ok) {
    const message =
      data && typeof data === "object" && "error" in data && typeof data.error === "string"
        ? data.error
        : `${response.status} ${response.statusText}`;
    throw new ApiError(message, response.status);
  }
  return data;
}

function postJson(path, body) {
  return request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export const api = {
  health: () => (request("/api/health")),

  stats: () => (request("/api/stats")),

  listEmails: (query) => (request(`/api/emails?${listParams(query)}`)),

  getEmail: (id) => (request(`/api/emails/${encodeURIComponent(id)}`)),

  analyzeFiles: (files) => {
    const form = new FormData();
    for (const file of Array.from(files)) form.append("files", file, file.name);
    return (request("/api/analyze", { method: "POST", body: form }));
  },

  analyzeFilesAsync: (files) => {
    const form = new FormData();
    for (const file of Array.from(files)) form.append("files", file, file.name);
    return (request("/api/analyze/async", { method: "POST", body: form }));
  },

  jobs: (ids) => (request(`/api/jobs?ids=${encodeURIComponent(ids.join(","))}`)),

  analyzeRaw: (raw) => (postJson("/api/analyze/raw", { raw, filename: "pasted.eml" })),

  getExplanation: (id) =>
    (request(`/api/emails/${encodeURIComponent(id)}/explanation`)),

  getDecision: (id) => (request(`/api/emails/${encodeURIComponent(id)}/decision`)),

  recordDecision: (id, action) =>
    (request(`/api/emails/${encodeURIComponent(id)}/${action}`, { method: "POST" })),

  listCampaigns: () => (request("/api/campaigns")),

  getCampaign: (id) => (request(`/api/campaigns/${encodeURIComponent(id)}`)),

  listAlerts: ({ limit = 100, unacknowledgedOnly = false } = {}) =>
    (request(`/api/alerts?limit=${limit}&unacknowledged_only=${unacknowledgedOnly}`)),

  acknowledgeAlert: (id) => request(`/api/alerts/${encodeURIComponent(id)}/ack`, { method: "POST" }),

  getCustody: (id) => (request(`/api/custody/${encodeURIComponent(id)}`)),

  verifyCustody: () => (request("/api/custody/verify")),
};

export const urls = {
  report: (id, format) => withMask(`/api/reports/${encodeURIComponent(id)}?format=${format}`),

  rawMessage: (id) => `/api/emails/${encodeURIComponent(id)}/raw`,

  exportCsv: (query) => withMask(`/api/emails/export.csv?${listParams(query)}`),

  alertSocket: (mask) => {
    const scheme = location.protocol === "https:" ? "wss://" : "ws://";
    return `${scheme}${location.host}/api/alerts/ws${mask ? "?mask=true" : ""}`;
  },

  alertStream: (mask) => `/api/alerts/stream${mask ? "?mask=true" : ""}`,
};
