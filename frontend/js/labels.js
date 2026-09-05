// @ts-check
/**
 * Plain-English names for everything the engine reports, with the technical
 * term in brackets where a panel would expect it.  Pure data: changing the
 * wording of the dashboard means changing this file and nothing else.
 *
 * Each entry names a *tone* ("bad", "ok"), never a colour; css/base.css maps
 * tones to the palette.
 */

/** @typedef {import('./types.js').ThreatCategory} ThreatCategory */
/** @typedef {import('./types.js').Severity} Severity */
/** @typedef {import('./types.js').SourceType} SourceType */
/** @typedef {import('./types.js').CaseStatus} CaseStatus */
/** @typedef {import('./types.js').NodeType} NodeType */
/** @typedef {import('./types.js').BecPatternName} BecPatternName */
/** @typedef {'ok' | 'warn' | 'bad' | 'info' | 'purple' | 'teal' | 'orange' | 'brand' | 'neutral' | 'ink'} Tone */

/** @typedef {{ label: string, blurb: string, tone: Tone }} CategoryLabel */

/** @type {Record<ThreatCategory, CategoryLabel>} */
export const CATEGORY = {
  Legitimate: { label: "Looks genuine", blurb: "Nothing suspicious found.", tone: "ok" },
  Suspicious: { label: "Suspicious", blurb: "Some warning signs. Treat with care.", tone: "warn" },
  Impersonated: { label: "Pretending to be someone", blurb: "Poses as a person, brand or department.", tone: "purple" },
  Phishing: { label: "Phishing", blurb: "Trying to steal passwords or personal details.", tone: "bad" },
  "Fraud-Related": { label: "Money fraud", blurb: "Trying to get money transferred or fees paid.", tone: "orange" },
};

/** @type {CategoryLabel} */
const UNKNOWN_CATEGORY = { label: "Unknown", blurb: "", tone: "neutral" };

/** @type {Record<Severity, { label: string, tone: Tone }>} */
export const SEVERITY = {
  info: { label: "info", tone: "neutral" },
  low: { label: "low", tone: "ok" },
  medium: { label: "medium", tone: "warn" },
  high: { label: "high", tone: "orange" },
  critical: { label: "critical", tone: "bad" },
};

/** @type {Record<SourceType, { title: string, detail: string }>} */
export const SOURCE_TYPE = {
  spoofed_domain: {
    title: "The real domain was faked",
    detail: "Someone forged a genuine company's address (spoofed domain).",
  },
  lookalike_domain: {
    title: "A copycat domain was used",
    detail: "The attacker registered a similar-looking domain (lookalike domain).",
  },
  compromised_account: {
    title: "A real account was hijacked",
    detail: "The mail passed every sender check, so a genuine mailbox was most likely broken into (compromised account).",
  },
  direct_attacker_infrastructure: {
    title: "Sent from the attacker's own setup",
    detail: "Came from a server or throwaway mailbox the attacker controls directly.",
  },
  legitimate_sender: { title: "Genuine sender", detail: "The sender is who they claim to be." },
  undetermined: {
    title: "Not enough evidence",
    detail: "The signals are not strong enough to say where this came from.",
  },
};

/** @type {Record<string, string>} */
export const MODULE = {
  headers: "Email headers",
  auth: "Sender checks",
  urls: "Links",
  attachments: "Attachments",
  nlp: "Wording",
  domains: "Domains",
  geoip: "Location & network",
  intel: "Threat intel",
  scoring: "Scoring",
};

/** @type {Record<BecPatternName, string>} */
export const BEC_PATTERN = {
  payment_diversion: "Payment redirected to a new bank account",
  fake_invoice: "Fake or pressured invoice",
  credential_harvesting: "Password / OTP harvesting",
  executive_impersonation: "Pretending to be a boss",
};

/** @type {Record<string, string>} */
export const CUSTODY_ACTION = {
  ingested: "email received",
  analyzed: "analysed",
  report_generated: "report made",
  exported: "downloaded",
  viewed_unmasked: "viewed in full",
  quarantine_decision: "marked for quarantine",
  block_decision: "marked for blocking",
};

/**
 * Analyst decisions.  These describe a decision *recorded in MailTrace*,
 * never an action taken in a mail system - the wording says so on purpose.
 * @type {Record<CaseStatus, { label: string, tone: Tone }>}
 */
export const DECISION = {
  open: { label: "No decision recorded", tone: "neutral" },
  quarantined: { label: "Marked for quarantine", tone: "warn" },
  blocked: { label: "Marked for blocking", tone: "bad" },
};

/** @type {Record<string, string>} */
export const DOMAIN_ROLE = {
  sender: "the sender",
  reply_to: "replies go here",
  return_path: "return address",
  url: "linked site",
  message_id: "message id",
};

/** @type {Record<NodeType, { label: string, tone: Tone }>} */
export const NODE_TYPE = {
  email: { label: "this email", tone: "brand" },
  address: { label: "email address", tone: "teal" },
  domain: { label: "domain", tone: "purple" },
  ip: { label: "IP address", tone: "bad" },
  asn: { label: "network owner", tone: "neutral" },
  url: { label: "link", tone: "warn" },
  attachment: { label: "attachment", tone: "ok" },
  campaign: { label: "attack group", tone: "ink" },
};

/** The five Stage 4 pillars, in the order the deck lists them. */
export const PILLARS = /** @type {const} */ ([
  ["auth", "Sender checks (Auth)"],
  ["text", "Wording of the message (Text)"],
  ["url", "Links and domains (URL)"],
  ["network", "Where it came from (Network)"],
  ["entropy", "Attached files (Entropy)"],
]);

/**
 * @param {string | null | undefined} category
 * @returns {CategoryLabel}
 */
export function categoryOf(category) {
  if (category && category in CATEGORY) return CATEGORY[/** @type {ThreatCategory} */ (category)];
  return category ? { ...UNKNOWN_CATEGORY, label: category } : UNKNOWN_CATEGORY;
}

/**
 * @param {string | null | undefined} severity
 */
export function severityOf(severity) {
  if (severity && severity in SEVERITY) return SEVERITY[/** @type {Severity} */ (severity)];
  return SEVERITY.info;
}

/**
 * The tone for a 0-100 score: the same thresholds the severity scale uses.
 * @param {number} score
 * @returns {Tone}
 */
export function toneForScore(score) {
  if (score >= 75) return "bad";
  if (score >= 50) return "orange";
  if (score >= 25) return "warn";
  return "ok";
}

/**
 * @param {number} score
 * @returns {Severity}
 */
export function severityForScore(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}
