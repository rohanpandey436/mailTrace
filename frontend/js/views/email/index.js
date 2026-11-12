import { api, urls } from "../../api.js";
import { flag, formatDate, percent, place } from "../../format.js";
import { useAsync, usePageTitle } from "../../hooks.js";
import { SOURCE_TYPE, categoryOf, plain } from "../../labels.js";
import { loadCytoscape, loadLeaflet, warmUp } from "../../libs.js";
import { Fragment, html, useEffect, useRef, useState } from "../../react.js";
import { session } from "../../state.js";
import { DecisionBar } from "../../ui/decision-bar.js";
import { GraphLegend, RelationshipGraph } from "../../ui/graph.js";
import { Menu } from "../../ui/menu.js";
import { RetentionBar } from "../../ui/retention-bar.js";
import { Explained, categoryChip, check, chip, errorState, gauge, loadingState, missingState, section } from "../../ui/primitives.js";
import { ContentTab } from "./content.js";
import { CustodyTab } from "./custody.js";
import { domainsTab } from "./domains.js";
import { findingsTab } from "./findings.js";
import { linksTab } from "./links.js";
import { TraceTab } from "./trace.js";

const TABS = [
  ["findings", "What we found"],
  ["trace", "Where it came from"],
  ["content", "How it tries to trick you"],
  ["links", "Links & files"],
  ["domains", "Domains & servers"],
  ["graph", "Connections"],
  ["custody", "Evidence log"],
];
const MAX_REASONS = 2;
const TAB_EDGE_PX = 8;
const TAB_KEYS = { ArrowRight: 1, ArrowLeft: -1, Home: "first", End: "last" };

function SenderChecks({ auth }) {
  const outcome = (value, failures) => (value === "pass" ? true : failures.includes(value) ? false : null);
  return html`<div class="checks">
    ${check("Allowed to send", auth.spf, outcome(auth.spf, ["fail", "softfail"]), "SPF: is this server permitted to send mail for that domain?")}
    ${check("Signature valid", auth.dkim, outcome(auth.dkim, ["fail"]), "DKIM: cryptographic signature added by the sending domain.")}
    ${check("Domain policy", auth.dmarc, outcome(auth.dmarc, ["fail"]), "DMARC: what the domain owner says to do when the checks fail.")}
  </div>`;
}

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
      <${Explained} title="Who really sent it" note="Our best assessment of the person or system behind this email." />
      <div class="cluster">${chip(source.title, "brand")} <span class="hint">${percent(attribution.confidence)} sure</span></div>
      <p class="hint subsection">${source.detail}</p>
      ${attribution.reasoning.length > 0 &&
      html`<ul class="hint">
        ${attribution.reasoning.slice(0, MAX_REASONS).map((reason, index) => html`<li key=${index}>${plain(reason)}</li>`)}
      </ul>`}
    </div>
    <div class="card card--pad">
      <${Explained} title="Is the sender genuine?" note="Three standard checks every real company sets up (SPF, DKIM, DMARC)." />
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

function Tabs({ tabs, current, onChoose }) {
  const strip = useRef((null));
  const moveFocus = useRef(false);
  const [more, setMore] = useState("");

  useEffect(() => {
    const element = strip.current;
    if (!element) return undefined;
    const measure = () => {
      const before = element.scrollLeft > 1;
      const after = element.scrollLeft + element.clientWidth < element.scrollWidth - 1;
      setMore(before && after ? "both" : before ? "start" : after ? "end" : "");
    };
    measure();
    element.addEventListener("scroll", measure, { passive: true });
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => {
      element.removeEventListener("scroll", measure);
      observer.disconnect();
    };
  }, [tabs.length]);

  useEffect(() => {
    const element = strip.current;
    const chosen = element?.querySelector('[aria-selected="true"]');
    if (!element || !(chosen instanceof HTMLElement)) return;
    const start = chosen.offsetLeft;
    const end = start + chosen.offsetWidth;
    if (start < element.scrollLeft) element.scrollLeft = start - TAB_EDGE_PX;
    else if (end > element.scrollLeft + element.clientWidth) element.scrollLeft = end - element.clientWidth + TAB_EDGE_PX;
    if (moveFocus.current) chosen.focus({ preventScroll: true });
    moveFocus.current = false;
  }, [current]);

  const onKeyDown = (event) => {
    const step = TAB_KEYS[event.key];
    if (step === undefined) return;
    event.preventDefault();
    const last = tabs.length - 1;
    const index = tabs.findIndex(([name]) => name === current);
    const next = step === "first" ? 0 : step === "last" ? last : (index + step + tabs.length) % tabs.length;
    moveFocus.current = true;
    onChoose(tabs[next][0]);
  };

  return html`<div
    class=${`tabs${more ? ` tabs--more-${more}` : ""}`}
    role="tablist"
    aria-label="Parts of this report"
    ref=${strip}
    onKeyDown=${onKeyDown}
  >
    ${tabs.map(
      ([name, label]) => html`<button
        key=${name}
        id=${`tab-${name}`}
        class=${`tab${current === name ? " is-active" : ""}`}
        type="button"
        role="tab"
        aria-selected=${String(current === name)}
        aria-controls="tab-panel"
        tabIndex=${current === name ? 0 : -1}
        onClick=${() => onChoose(name)}
      >
        ${label}
      </button>`,
    )}
  </div>`;
}

export function EmailView({ emailId }) {
  const { data: result, error, missing, loading, slow, reload } = useAsync(() => api.getEmail(emailId), [emailId]);
  const [tab, setTab] = useState(session.emailTab);

  const choose = (next) => {
    session.emailTab = next;
    setTab(next);
  };

  usePageTitle(result ? result.email.subject || "Email with no subject" : "Checked email");
  useEffect(() => {
    warmUp(loadLeaflet);
    warmUp(loadCytoscape);
  }, []);

  if (missing) {
    return missingState(
      "This email is not here",
      "It may have been deleted when its keeping period ended, or the link is incomplete.",
      "#/cases",
      "Back to checked emails",
    );
  }
  if (error) return errorState(error, reload);
  if (loading || !result) return loadingState(4, slow);

  const { email } = result;
  const noHeaders = result.headers.hops.length === 0;

  return html`<${Fragment}>
    <a href="#/cases" class="back-link">← Back to checked emails</a>
    <div class="cluster cluster--between cluster--top section">
      <div class="spread spread--wide">
        <h1 class="page-title page-title--sm">${email.subject || html`<span class="muted">(no subject)</span>`}</h1>
        <div class="hint cluster cluster--loose">
          <span>
            From <b class="strong">${email.sender.display_name || "unnamed"}</b>${" "}
            <span class="mono">${`<${email.sender.address}>`}</span>
          </span>
          <span>${email.date ? `Sent ${formatDate(email.date)}` : "Send time not recorded"}</span>
          <span class="mono">${result.filename}</span>
          ${result.campaign_id &&
          html`<a class="link" href=${`#/campaigns/${encodeURIComponent(result.campaign_id)}`}>See linked attacks →</a>`}
        </div>
      </div>
      <div class="cluster">
        <a class="btn btn--primary" target="_blank" rel="noopener" href=${urls.report(result.id, "pdf")} title="Section 65B compliant legal report">
          Legal PDF report
        </a>
        <${Menu} label="Export" caret>
          <a class="menu__item" target="_blank" rel="noopener" href=${urls.report(result.id, "html")}>
            View report in browser<span class="menu__hint">The full report as a web page</span>
          </a>
          <a class="menu__item" href=${urls.report(result.id, "csv")}>
            Spreadsheet (CSV)<span class="menu__hint">Verdict, scores, origin, indicators and findings</span>
          </a>
          <a class="menu__item" href=${urls.rawMessage(result.id)}>
            Download original<span class="menu__hint">The email exactly as it was received</span>
          </a>
        </${Menu}>
      </div>
    </div>
    <${VerdictCards} result=${result} />
    ${noHeaders &&
    html`<div class="note note--warn section">
      <b>This email carried no delivery headers, so we could not trace where it came from.</b> You most likely pasted only the visible
      message. Use <i>Download message</i> in Gmail, or <i>View message source</i> and copy everything from the very first line. The
      wording and link checks below still worked normally.
    </div>`}
    <${OriginStrip} result=${result} />
    <${RetentionBar} emailId=${result.id} />
    <div class="section"><${DecisionBar} emailId=${result.id} /></div>
    <div class="tabs-row">
      <${Tabs} tabs=${TABS} current=${tab} onChoose=${choose} />
    </div>
    <div class="tab-panel" id="tab-panel" role="tabpanel" aria-labelledby=${`tab-${tab}`} key=${tab}>
      <${TabPanel} result=${result} tab=${tab} />
    </div>
  </>`;
}
