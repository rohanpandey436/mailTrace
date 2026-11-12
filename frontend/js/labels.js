export const CATEGORY = {
  Legitimate: { label: "Looks genuine", blurb: "Nothing suspicious found.", tone: "ok" },
  Suspicious: { label: "Suspicious", blurb: "Some warning signs. Treat with care.", tone: "warn" },
  Impersonated: { label: "Pretending to be someone", blurb: "Poses as a person, brand or department.", tone: "purple" },
  Phishing: { label: "Phishing", blurb: "Trying to steal passwords or personal details.", tone: "bad" },
  "Fraud-Related": { label: "Money fraud", blurb: "Trying to get money transferred or fees paid.", tone: "orange" },
};

const UNKNOWN_CATEGORY = { label: "Unknown", blurb: "", tone: "neutral" };

export const SEVERITY = {
  info: { label: "info", tone: "neutral" },
  low: { label: "low", tone: "ok" },
  medium: { label: "medium", tone: "warn" },
  high: { label: "high", tone: "orange" },
  critical: { label: "critical", tone: "bad" },
};

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

export const BEC_PATTERN = {
  payment_diversion: "Payment redirected to a new bank account",
  fake_invoice: "Fake or pressured invoice",
  credential_harvesting: "Password / OTP harvesting",
  executive_impersonation: "Pretending to be a boss",
  extortion: "Money demanded under threat",
  violent_threat: "Threat of violence or stalking",
  investment_scam: "Fake investment returns",
  callback_scam: "Fake tech-support call-back",
};

export const CUSTODY_ACTION = {
  ingested: "email received",
  analyzed: "analysed",
  report_generated: "report made",
  exported: "downloaded",
  viewed_unmasked: "viewed in full",
  quarantine_decision: "marked for quarantine",
  block_decision: "marked for blocking",
  retention_set: "set to delete itself",
  evidence_frozen: "frozen as evidence",
  purged: "deleted, period ended",
};

export const ORIGIN = {
  dashboard: {
    title: "Temporary case",
    detail: "This case was submitted with a retention period.",
  },
  gmail: {
    title: "Sent from Gmail",
    detail: "This email was sent here from the MailTrace add-on in Gmail because its owner pressed Investigate.",
  },
  sample: {
    title: "Sample email",
    detail: "This is one of MailTrace's built-in example emails, checked in exactly the same way as a real one.",
  },
};

export const SAMPLES = [
  ["phishing_sbi_kyc", "Bank KYC phishing"],
  ["impersonation_ceo_gift_cards", "Boss asks for gift cards"],
  ["bec_payment_diversion", "Changed bank details"],
  ["fraud_lottery_advance_fee", "Lottery prize fee"],
  ["legit_transactional", "A genuine email"],
];

export const DECISION = {
  open: { label: "No decision recorded", tone: "neutral" },
  quarantined: { label: "Marked for quarantine", tone: "warn" },
  blocked: { label: "Marked for blocking", tone: "bad" },
};

export const DOMAIN_ROLE = {
  sender: "the sender",
  reply_to: "replies go here",
  return_path: "return address",
  url: "linked site",
  message_id: "message id",
};

export const LOOKALIKE = {
  typosquat: "one or two letters changed",
  homoglyph: "look-alike letters swapped in",
  punycode: "foreign letters that look the same",
  tld_swap: "same name with a different ending",
  extra_token: "extra words added to the real name",
  subdomain_abuse: "real name used as a prefix",
};

export const REPUTATION = {
  disposable: "throwaway address service",
  suspicious_tld: "risky domain ending",
  urlhaus: "listed for spreading malware",
};

const INDICATOR = {
  ip: ["Same sending computer", "sending computer"],
  sender: ["Same sender", "sender"],
  domain: ["Same sender domain", "sender domain"],
  replyto: ["Same reply address", "reply address"],
  urlhost: ["Same linked site", "linked site"],
  file: ["Same attached file", "attached file"],
  subject: ["Same subject line", "subject line"],
  asn: ["Same network owner", "network owner"],
  mailer: ["Same mail program", "mail program"],
  simhash: ["Nearly identical wording", "wording"],
  tlsh: ["Nearly identical wording", "wording"],
};

const FINGERPRINT_KINDS = new Set(["simhash", "tlsh"]);
const FILE_HASH_CHARS = 12;
const LOOKALIKE_CODES = Object.keys(LOOKALIKE).join("|");
const LOOKALIKE_CODE = new RegExp(`\\((${LOOKALIKE_CODES})\\)`, "g");
const LOOKALIKE_PHRASE = new RegExp(` using the (${LOOKALIKE_CODES.replaceAll("_", " ")}) technique`, "g");

export function indicatorOf(raw) {
  const match = /^([a-z0-9]+)([:~])(.*)$/s.exec(raw);
  const known = match ? INDICATOR[match[1]] : undefined;
  if (!match || !known) return { label: "", value: raw, noun: raw };
  const [, kind, , rest] = match;
  if (FINGERPRINT_KINDS.has(kind)) return { label: known[0], value: "", noun: known[1] };
  const value = kind === "file" && rest.length > FILE_HASH_CHARS ? `${rest.slice(0, FILE_HASH_CHARS)}…` : rest;
  return { label: known[0], value, noun: known[1] };
}

export function sharedNouns(indicators) {
  const nouns = [...new Set(indicators.map((raw) => indicatorOf(raw).noun))];
  if (nouns.length <= 1) return nouns.join("");
  return `${nouns.slice(0, -1).join(", ")} and ${nouns[nouns.length - 1]}`;
}

export function plain(text) {
  return (text ?? "")
    .replace(LOOKALIKE_CODE, (_, code) => `(${LOOKALIKE[code]})`)
    .replace(LOOKALIKE_PHRASE, (_, words) => ` (${LOOKALIKE[words.replaceAll(" ", "_")]})`);
}

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

export const PILLARS = ([
  ["auth", "Sender checks (Auth)"],
  ["text", "Wording of the message (Text)"],
  ["url", "Links and domains (URL)"],
  ["network", "Where it came from (Network)"],
  ["entropy", "Attached files (Entropy)"],
]);

export function categoryOf(category) {
  if (category && category in CATEGORY) return CATEGORY[(category)];
  return category ? { ...UNKNOWN_CATEGORY, label: category } : UNKNOWN_CATEGORY;
}

export function severityOf(severity) {
  if (severity && severity in SEVERITY) return SEVERITY[(severity)];
  return SEVERITY.info;
}

export function toneForScore(score) {
  if (score >= 75) return "bad";
  if (score >= 50) return "orange";
  if (score >= 25) return "warn";
  return "ok";
}

export function severityForScore(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}
