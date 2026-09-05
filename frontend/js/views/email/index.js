// @ts-check
/** One checked email: the verdict, who really sent it, the sender checks, the origin, and the tabs. */
import { api, urls } from "../../api.js";
import { flag, formatDate, percent, place } from "../../format.js";
import { useAsync } from "../../hooks.js";
import { SOURCE_TYPE, categoryOf } from "../../labels.js";
import { Fragment, html, useState } from "../../react.js";
import { preferences, session, setPreference } from "../../state.js";
import { DecisionBar } from "../../ui/decision-bar.js";
import { GraphLegend, RelationshipGraph } from "../../ui/graph.js";
import { categoryChip, check, chip, errorState, gauge, section, skeleton } from "../../ui/primitives.js";
import { ContentTab } from "./content.js";
import { CustodyTab } from "./custody.js";
import { domainsTab } from "./domains.js";
import { findingsTab } from "./findings.js";
import { linksTab } from "./links.js";
import { TraceTab } from "./trace.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').AuthResult} AuthResult */
/** @typedef {import('../../state.js').EmailTab} EmailTab */

/** @type {Array<[EmailTab, string]>} */
const TABS = [
  ["findings", "What we found"],
  ["trace", "Where it came from"],
  ["content", "How it tries to trick you"],
  ["links", "Links & files"],
  ["domains", "Domains & servers"],
];
/** Shown only with the advanced view switched on. */
/** @type {Array<[EmailTab, string]>} */
const ADVANCED_TABS = [
  ["graph", "Connections"],
  ["custody", "Evidence log"],
];
const DEFAULT_TAB = "findings";
const MAX_REASONS = 2;

/**
 * @param {EmailTab} tab
 */
function isAdvanced(tab) {
  return ADVANCED_TABS.some(([name]) => name === tab);
}

/**
 * @param {{ auth: AuthResult }} props
 */
function SenderChecks({ auth }) {
  /** @param {string} value @param {string[]} failures */
  const outcome = (value, failures) => (value === "pass" ? true : failures.includes(value) ? false : null);
  return html`<div class="checks">
    ${check("Allowed to send", auth.spf, outcome(auth.spf, ["fail", "softfail"]), "SPF: is this server permitted to send mail for that domain?")}
    ${check("Signature valid", auth.dkim, outcome(auth.dkim, ["fail"]), "DKIM: cryptographic signature added by the sending domain.")}
    ${check("Domain policy", auth.dmarc, outcome(auth.dmarc, ["fail"]), "DMARC: what the domain owner says to do when the checks fail.")}
  </div>`;
}

/**
 * @param {{ result: AnalysisResult }} props
 */
function VerdictCards({ result }) {
  const { verdict, attribution, headers } = result;
  const category = categoryOf(verdict.category);
  const source = SOURCE_TYPE[attribution.source_type] ?? SOURCE_TYPE.undetermined;
  const addressesClean = !headers.reply_to_mismatch && !headers.return_path_mismatch && !headers.display_name_spoof;
  return html`<div class="grid grid--verdict section">
    <div class="card card--pad verdict">
      ${gauge(verdict.risk_score, verdict.severity)}
      <div>${categoryChip(verdict.category)}</div>
      <p class="hint verdict__blurb">${category.blurb}</p>
      <p class="hint verdict__blurb">We are <b class="strong">${percent(verdict.confidence)}</b> sure of this.</p>
    </div>
    <div class="card card--pad">
      <h3 class="section__title">Who really sent it</h3>
      <p class="hint section__note">Our best assessment of the person or system behind this email.</p>
      <div class="cluster">${chip(source.title, "brand")} <span class="hint">${percent(attribution.confidence)} sure</span></div>
      <p class="hint subsection">${source.detail}</p>
      ${attribution.reasoning.length > 0 &&
      html`<ul class="hint">
        ${attribution.reasoning.slice(0, MAX_REASONS).map((reason, index) => html`<li key=${index}>${reason}</li>`)}
      </ul>`}
    </div>
    <div class="card card--pad">
      <h3 class="section__title">Is the sender genuine?</h3>
      <p class="hint section__note">Three standard checks every real company sets up (SPF, DKIM, DMARC).</p>
      <${SenderChecks} auth=${headers.auth} />
      <div class="cluster">
        ${headers.reply_to_mismatch && chip("Replies go somewhere else", "bad")}
        ${headers.return_path_mismatch && chip("Return address differs", "warn")}
        ${headers.display_name_spoof &&
        chip(`Display name is fake${headers.display_name_brand ? ` (${headers.display_name_brand})` : ""}`, "bad")}
        ${addressesClean && chip("Nothing odd in the addresses", "ok")}
      </div>
    </div>
  </div>`;
}

/**
 * @param {{ result: AnalysisResult }} props
 */
function OriginStrip({ result }) {
  const { headers, infrastructure: infra } = result;
  const geo = infra.origin_geo;
  return html`<div class="card card--tight section cluster cluster--loose origin-strip">
    <span class="strong">Origin:</span>
    ${headers.originating_ip
      ? html`<span class="mono strong">${headers.originating_ip}</span>`
      : html`<span class="muted">could not be traced</span>`}
    ${geo?.country && html`<span>${flag(geo.country_code)} ${place([geo.city, geo.country])}</span>`}
    ${geo?.isp && html`<span class="muted">${geo.isp}</span>`}
    ${infra.tor_exit && chip("Anonymity network (Tor)", "bad")}
    ${infra.vpn_or_proxy && chip("VPN or proxy", "warn")}
    ${infra.hosting_provider && chip("Rented server, not a home or office", "warn")}
    ${infra.blacklisted && chip("Known bad address (on a blocklist)", "bad")}
  </div>`;
}

/**
 * @param {{ result: AnalysisResult, tab: EmailTab }} props
 */
function TabPanel({ result, tab }) {
  switch (tab) {
    case "trace":
      return html`<${TraceTab} result=${result} />`;
    case "content":
      return html`<${ContentTab} result=${result} />`;
    case "links":
      return linksTab(result);
    case "domains":
      return domainsTab(result);
    case "graph":
      return section("Connections", html`<${Fragment}><${RelationshipGraph} graph=${result.graph} /><${GraphLegend} /></>`, {
        note: "Everything this email touches, drawn as a map. Useful for spotting the same server or address turning up in other attacks.",
      });
    case "custody":
      return html`<${CustodyTab} result=${result} />`;
    default:
      return findingsTab(result);
  }
}

/**
 * @param {{ emailId: string }} props
 */
export function EmailView({ emailId }) {
  const { data: result, error, loading, reload } = useAsync(() => api.getEmail(emailId), [emailId]);
  const [advanced, setAdvanced] = useState(preferences.advanced);
  // Remembered across cases for the session, so paging through a campaign keeps
  // whichever tab the analyst is working in.
  const [tab, setTab] = useState(() => (isAdvanced(session.emailTab) && !preferences.advanced ? DEFAULT_TAB : session.emailTab));

  /** @param {EmailTab} next */
  const choose = (next) => {
    session.emailTab = next;
    setTab(next);
  };

  const toggleAdvanced = () => {
    const next = !advanced;
    setPreference("advanced", next);
    setAdvanced(next);
    if (!next && isAdvanced(tab)) choose(DEFAULT_TAB);
  };

  if (error) return errorState(error, reload);
  if (loading || !result) return skeleton(4);

  const { email } = result;
  const noHeaders = result.headers.hops.length === 0;
  /** @param {Array<[EmailTab, string]>} tabs */
  const tabButtons = (tabs) =>
    tabs.map(
      ([name, label]) => html`<button
        key=${name}
        class=${`tab${tab === name ? " is-active" : ""}`}
        type="button"
        onClick=${() => choose(name)}
      >
        ${label}
      </button>`,
    );

  return html`<${Fragment}>
    <a href="#/cases" class="back-link">← Back to checked emails</a>
    <div class="cluster cluster--between cluster--top section">
      <div class="spread">
        <h1 class="page-title page-title--sm">${email.subject || html`<span class="muted">(no subject)</span>`}</h1>
        <div class="hint cluster cluster--loose">
          <span>
            From <b class="strong">${email.sender.display_name || "unnamed"}</b>
            <span class="mono">&lt;${email.sender.address}&gt;</span>
          </span>
          <span>Sent ${formatDate(email.date)}</span>
          <span class="mono">${result.filename}</span>
        </div>
      </div>
      <div class="cluster">
        <a class="btn btn--primary" target="_blank" rel="noopener" href=${urls.report(result.id, "pdf")} title="Section 65B compliant legal report">
          Legal PDF report
        </a>
        <a class="btn" target="_blank" rel="noopener" href=${urls.report(result.id, "html")}>View in browser</a>
        <a class="btn" href=${urls.report(result.id, "csv")} title="The verdict, the score breakdown, the origin, the indicators and every finding, as a spreadsheet">
          Spreadsheet (CSV)
        </a>
        <a class="btn" href=${urls.rawMessage(result.id)}>Download original</a>
        ${result.campaign_id &&
        html`<a class="btn" href=${`#/campaigns/${encodeURIComponent(result.campaign_id)}`}>See linked attacks</a>`}
      </div>
    </div>
    <div class="section"><${DecisionBar} emailId=${result.id} /></div>
    ${noHeaders &&
    html`<div class="note note--warn section">
      <b>This email carried no delivery headers, so we could not trace where it came from.</b> You most likely pasted only the visible
      message. Use <i>Download message</i> in Gmail, or <i>View message source</i> and copy everything from the very first line. The
      wording and link checks below still worked normally.
    </div>`}
    <${VerdictCards} result=${result} />
    <${OriginStrip} result=${result} />
    <div class="tabs-row">
      <div class="tabs">
        ${tabButtons(TABS)} ${advanced && html`<span class="tabs">${tabButtons(ADVANCED_TABS)}</span>`}
      </div>
      <label class="switch-label" title="Shows the connection map and the tamper-proof evidence log">
        <span>Advanced view</span>
        <span
          class=${`switch${advanced ? " is-on" : ""}`}
          role="switch"
          tabIndex=${0}
          aria-checked=${String(advanced)}
          onClick=${toggleAdvanced}
          onKeyDown=${(/** @type {KeyboardEvent} */ event) => {
            if (event.key === " " || event.key === "Enter") {
              event.preventDefault();
              toggleAdvanced();
            }
          }}
        ></span>
      </label>
    </div>
    <${TabPanel} result=${result} tab=${tab} />
  </>`;
}
