// @ts-check
/**
 * The backend API, one function per endpoint.
 *
 * The only module that calls `fetch`. Every request carries the PII-mask
 * preference and a failure becomes an `ApiError`, so views never see a
 * `Response` or raw JSON.
 */
import { preferences } from "./state.js";

/** @typedef {import('./types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('./types.js').AnalyzeResponse} AnalyzeResponse */
/** @typedef {import('./types.js').Alert} Alert */
/** @typedef {import('./types.js').Campaign} Campaign */
/** @typedef {import('./types.js').CampaignDetail} CampaignDetail */
/** @typedef {import('./types.js').CaseDecision} CaseDecision */
/** @typedef {import('./types.js').CustodyChain} CustodyChain */
/** @typedef {import('./types.js').CustodyVerification} CustodyVerification */
/** @typedef {import('./types.js').DashboardStats} DashboardStats */
/** @typedef {import('./types.js').EmailListResponse} EmailListResponse */
/** @typedef {import('./types.js').AsyncAnalyzeResponse} AsyncAnalyzeResponse */
/** @typedef {import('./types.js').Health} Health */
/** @typedef {import('./types.js').JobStatus} JobStatus */
/** @typedef {import('./types.js').LimeReport} LimeReport */

/** @typedef {{ q?: string, category?: string, minRisk?: number, limit?: number, offset?: number }} ListQuery */
/** @typedef {'pdf' | 'html' | 'csv' | 'json'} ReportFormat */
/** @typedef {'quarantine' | 'block'} DecisionAction */

export class ApiError extends Error {
  /**
   * @param {string} message
   * @param {number} status
   */
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/**
 * The message to show a person for a failure of any shape.
 * @param {unknown} error
 */
export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * @param {string} path
 * @returns {string}
 */
function withMask(path) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}mask=${preferences.mask ? "true" : "false"}`;
}

/**
 * @param {ListQuery} query
 */
function listParams(query) {
  const params = new URLSearchParams();
  if (query.q) params.set("q", query.q);
  if (query.category) params.set("category", query.category);
  if (query.minRisk) params.set("min_risk", String(query.minRisk));
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset) params.set("offset", String(query.offset));
  return params.toString();
}

/**
 * @param {string} path
 * @param {RequestInit} [init]
 * @returns {Promise<unknown>}
 */
async function request(path, init) {
  const response = await fetch(withMask(path), init);
  const text = await response.text();
  /** @type {unknown} */
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

/**
 * @param {string} path
 * @param {unknown} body
 */
function postJson(path, body) {
  return request(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

export const api = {
  /** @returns {Promise<Health>} */
  health: () => /** @type {Promise<Health>} */ (request("/api/health")),

  /** @returns {Promise<DashboardStats>} */
  stats: () => /** @type {Promise<DashboardStats>} */ (request("/api/stats")),

  /**
   * @param {ListQuery} query
   * @returns {Promise<EmailListResponse>}
   */
  listEmails: (query) => /** @type {Promise<EmailListResponse>} */ (request(`/api/emails?${listParams(query)}`)),

  /**
   * @param {string} id
   * @returns {Promise<AnalysisResult>}
   */
  getEmail: (id) => /** @type {Promise<AnalysisResult>} */ (request(`/api/emails/${encodeURIComponent(id)}`)),

  /**
   * @param {FileList | File[]} files
   * @returns {Promise<AnalyzeResponse>}
   */
  analyzeFiles: (files) => {
    const form = new FormData();
    for (const file of Array.from(files)) form.append("files", file, file.name);
    return /** @type {Promise<AnalyzeResponse>} */ (request("/api/analyze", { method: "POST", body: form }));
  },

  /**
   * The same upload through the Celery queue: returns job ids straight away
   * instead of waiting for the analyses. Used for batches, where holding one
   * request open for every message would time out long before the work did.
   * @param {FileList | File[]} files
   * @returns {Promise<AsyncAnalyzeResponse>}
   */
  analyzeFilesAsync: (files) => {
    const form = new FormData();
    for (const file of Array.from(files)) form.append("files", file, file.name);
    return /** @type {Promise<AsyncAnalyzeResponse>} */ (request("/api/analyze/async", { method: "POST", body: form }));
  },

  /**
   * Poll a whole batch in one request rather than one per job.
   * @param {string[]} ids
   * @returns {Promise<JobStatus[]>}
   */
  jobs: (ids) => /** @type {Promise<JobStatus[]>} */ (request(`/api/jobs?ids=${encodeURIComponent(ids.join(","))}`)),

  /**
   * @param {string} raw
   * @returns {Promise<AnalyzeResponse>}
   */
  analyzeRaw: (raw) => /** @type {Promise<AnalyzeResponse>} */ (postJson("/api/analyze/raw", { raw, filename: "pasted.eml" })),

  /**
   * The LIME explanation. Fitted on the first request for a case, then cached
   * server-side, so this is slow once and instant afterwards.
   * @param {string} id
   * @returns {Promise<LimeReport>}
   */
  getExplanation: (id) =>
    /** @type {Promise<LimeReport>} */ (request(`/api/emails/${encodeURIComponent(id)}/explanation`)),

  /**
   * @param {string} id
   * @returns {Promise<CaseDecision>}
   */
  getDecision: (id) => /** @type {Promise<CaseDecision>} */ (request(`/api/emails/${encodeURIComponent(id)}/decision`)),

  /**
   * @param {string} id
   * @param {DecisionAction} action
   * @returns {Promise<CaseDecision>}
   */
  recordDecision: (id, action) =>
    /** @type {Promise<CaseDecision>} */ (request(`/api/emails/${encodeURIComponent(id)}/${action}`, { method: "POST" })),

  /** @returns {Promise<Campaign[]>} */
  listCampaigns: () => /** @type {Promise<Campaign[]>} */ (request("/api/campaigns")),

  /**
   * @param {string} id
   * @returns {Promise<CampaignDetail>}
   */
  getCampaign: (id) => /** @type {Promise<CampaignDetail>} */ (request(`/api/campaigns/${encodeURIComponent(id)}`)),

  /**
   * @param {{ limit?: number, unacknowledgedOnly?: boolean }} [options]
   * @returns {Promise<Alert[]>}
   */
  listAlerts: ({ limit = 100, unacknowledgedOnly = false } = {}) =>
    /** @type {Promise<Alert[]>} */ (request(`/api/alerts?limit=${limit}&unacknowledged_only=${unacknowledgedOnly}`)),

  /**
   * @param {string} id
   */
  acknowledgeAlert: (id) => request(`/api/alerts/${encodeURIComponent(id)}/ack`, { method: "POST" }),

  /**
   * @param {string} id
   * @returns {Promise<CustodyChain>}
   */
  getCustody: (id) => /** @type {Promise<CustodyChain>} */ (request(`/api/custody/${encodeURIComponent(id)}`)),

  /** @returns {Promise<CustodyVerification>} */
  verifyCustody: () => /** @type {Promise<CustodyVerification>} */ (request("/api/custody/verify")),
};

/** Links the browser follows directly (downloads and reports). */
export const urls = {
  /**
   * @param {string} id
   * @param {ReportFormat} format
   */
  report: (id, format) => withMask(`/api/reports/${encodeURIComponent(id)}?format=${format}`),

  /** @param {string} id */
  rawMessage: (id) => `/api/emails/${encodeURIComponent(id)}/raw`,

  /** @param {ListQuery} query */
  exportCsv: (query) => withMask(`/api/emails/export.csv?${listParams(query)}`),

  /** @param {boolean} mask */
  alertSocket: (mask) => {
    const scheme = location.protocol === "https:" ? "wss://" : "ws://";
    return `${scheme}${location.host}/api/alerts/ws${mask ? "?mask=true" : ""}`;
  },

  /** @param {boolean} mask */
  alertStream: (mask) => `/api/alerts/stream${mask ? "?mask=true" : ""}`,
};
