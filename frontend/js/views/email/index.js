import { api, urls } from "../../api.js";
import { flag, formatDate, percent, place, plural } from "../../format.js";
import { useAsync, usePageTitle } from "../../hooks.js";
import { SOURCE_TYPE, categoryOf, plain } from "../../labels.js";
import { loadCytoscape, loadLeaflet, warmUp } from "../../libs.js";
import { Fragment, html, useEffect } from "../../react.js";
import { DecisionBar } from "../../ui/decision-bar.js";
import { GraphLegend, RelationshipGraph } from "../../ui/graph.js";
import { Menu } from "../../ui/menu.js";
import { RetentionBar } from "../../ui/retention-bar.js";
import {
  Explained,
  HeadingLevel,
  categoryChip,
  check,
  chip,
  errorState,
  gauge,
  loadingState,
  missingState,
  section,
} from "../../ui/primitives.js";
import { JumpBar, LazyMount, StorySection, jumpTo, useSections } from "../../ui/story.js";
import { ContentTab } from "./content.js";
import { CustodyTab } from "./custody.js";
import { domainCards, originComputer, seenBefore } from "./domains.js";
import { findingsTab } from "./findings.js";
import { linksTab } from "./links.js";
import { TraceTab } from "./trace.js";

const SECTIONS = [
  { id: "summary", label: "Verdict" },
  { id: "findings", label: "What we found" },
  { id: "sender", label: "Who sent it" },
  { id: "route", label: "Where it came from" },
  { id: "wording", label: "How it tricks you" },
  { id: "links", label: "Links & files" },
  { id: "domains", label: "Domains" },
  { id: "graph", label: "Connections" },
  { id: "evidence", label: "Evidence log" },
];
const MAX_REASONS = 2;
const HERO_REASONS = 3;
const HERO_STEPS = 2;
const CARD_HEADINGS = 3;

function VerdictHero({ result }) {
  const { verdict } = result;
  const category = categoryOf(verdict.category);
  const warnings = result.findings.filter((finding) => finding.severity !== "info");
  const steps = verdict.recommended_actions;
  return html`<div class="card hero">
    <div class="hero__gauge">${gauge(verdict.risk_score, verdict.severity)}</div>
    <div class="hero__body">
      <div class="cluster">
        ${categoryChip(verdict.category)}
        <span class="hint">We are <b class="strong">${percent(verdict.confidence)}</b> sure of this.</span>
      </div>
      <p class="hero__headline">${category.blurb || category.label}</p>
      <div class="hero__cols">
        <div>
          <h2 class="hero__label">${category.tone === "ok" ? "What we noticed" : "Why we think so"}</h2>
          ${warnings.length > 0
            ? html`<ul class="hero__list">
                ${warnings.slice(0, HERO_REASONS).map((finding) => html`<li key=${finding.id}>${plain(finding.title)}</li>`)}
              </ul>`
            : html`<p class="hero__none">No warning signs were found in this email.</p>`}
          ${warnings.length > HERO_REASONS &&
          html`<button type="button" class="linkbtn" onClick=${() => jumpTo("findings")}>
            See all ${plural(warnings.length, "finding")}
          </button>`}
        </div>
        ${steps.length > 0 &&
        html`<div>
          <h2 class="hero__label">What to do first</h2>
          <ol class="hero__list">
            ${steps.slice(0, HERO_STEPS).map((step, index) => html`<li key=${index}>${step}</li>`)}
          </ol>
          ${steps.length > HERO_STEPS &&
          html`<button type="button" class="linkbtn" onClick=${() => jumpTo("findings")}>See all ${plural(steps.length, "step")}</button>`}
        </div>`}
      </div>
    </div>
  </div>`;
}

function SenderChecks({ auth }) {
  const outcome = (value, failures) => (value === "pass" ? true : failures.includes(value) ? false : null);
  return html`<div class="checks">
    ${check("Allowed to send", auth.spf, outcome(auth.spf, ["fail", "softfail"]), "SPF: is this server permitted to send mail for that domain?")}
    ${check("Signature valid", auth.dkim, outcome(auth.dkim, ["fail"]), "DKIM: cryptographic signature added by the sending domain.")}
    ${check("Domain policy", auth.dmarc, outcome(auth.dmarc, ["fail"]), "DMARC: what the domain owner says to do when the checks fail.")}
  </div>`;
}

function SenderCards({ result }) {
  const { attribution, headers } = result;
  const source = SOURCE_TYPE[attribution.source_type] ?? SOURCE_TYPE.undetermined;
  const addressesClean = !headers.reply_to_mismatch && !headers.return_path_mismatch && !headers.display_name_spoof;
  return html`<div class="grid grid--2">
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

function CaseHead({ result }) {
  const { email } = result;
  return html`<div class="cluster cluster--between cluster--top section">
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
  </div>`;
}

function Report({ result }) {
  useSections(SECTIONS);
  useEffect(() => {
    warmUp(loadLeaflet);
    warmUp(loadCytoscape);
  }, []);
  const noHeaders = result.headers.hops.length === 0;

  return html`<${Fragment}>
    <a href="#/cases" class="back-link">← Back to checked emails</a>
    <${CaseHead} result=${result} />
    <${JumpBar} />
    <${StorySection} id="summary">
      <${VerdictHero} result=${result} />
      ${noHeaders &&
      html`<div class="note note--warn section">
        <b>This email carried no delivery headers, so we could not trace where it came from.</b> You most likely pasted only the
        visible message. Use <i>Download message</i> in Gmail, or <i>View message source</i> and copy everything from the very first
        line. The wording and link checks below still worked normally.
      </div>`}
      <${RetentionBar} emailId=${result.id} />
    </${StorySection}>
    <${HeadingLevel.Provider} value=${CARD_HEADINGS}>
      <${StorySection} id="findings" title="What we found" intro="Every warning sign, how the score was worked out, and what to do about it.">
        ${findingsTab(result)}
      </${StorySection}>
      <${StorySection} id="sender" title="Who sent it" intro="Whether the sender is who they claim to be.">
        <${SenderCards} result=${result} />
      </${StorySection}>
      <${StorySection} id="route" title="Where it came from" intro="The path the email took across the internet, traced from its hidden headers.">
        <${OriginStrip} result=${result} />
        <${LazyMount} height="30rem"><${TraceTab} result=${result} /></${LazyMount}>
        <div class="story__gap">${originComputer(result)}</div>
      </${StorySection}>
      <${StorySection} id="wording" title="How it tries to trick you" intro="What the message says, and how the rules and the trained model read it.">
        <${LazyMount} height="40rem"><${ContentTab} result=${result} /></${LazyMount}>
      </${StorySection}>
      <${StorySection} id="links" title="Links & files" intro="Where the links really lead and what is inside the attachments.">
        ${linksTab(result)}
      </${StorySection}>
      <${StorySection} id="domains" title="Domains" intro="The web addresses involved, and earlier emails that share something with this one.">
        ${seenBefore(result)} ${domainCards(result)}
      </${StorySection}>
      <${StorySection} id="graph" title="Connections" intro="How this email, its sender, its servers and its links are tied together.">
        <${LazyMount} height="32rem">
          ${section(
            "Everything this email touches",
            html`<${Fragment}><${RelationshipGraph} graph=${result.graph} /><${GraphLegend} /></>`,
            { note: "Useful for spotting the same server or address turning up in other attacks." },
          )}
        </${LazyMount}>
      </${StorySection}>
      <${StorySection} id="evidence" title="Evidence and decision" intro="Your decision on this case, and the tamper-proof record of everything done with it.">
        <div class="section"><${DecisionBar} emailId=${result.id} /></div>
        <${LazyMount} height="14rem"><${CustodyTab} result=${result} /></${LazyMount}>
      </${StorySection}>
    </${HeadingLevel.Provider}>
  </>`;
}

export function EmailView({ emailId }) {
  const { data: result, error, missing, loading, slow, reload } = useAsync(() => api.getEmail(emailId), [emailId]);
  usePageTitle(result ? result.email.subject || "Email with no subject" : "Checked email");

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
  return html`<${Report} result=${result} />`;
}
