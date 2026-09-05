// @ts-check
/**
 * "Domains & servers": the originating computer, earlier emails that share
 * something with this one, and every domain involved.
 */
import { html } from "../../dom.js";
import { flag, place, truncate } from "../../format.js";
import { DOMAIN_ROLE } from "../../labels.js";
import { chip, kv, section } from "../../ui/primitives.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').DomainIntel} DomainIntel */

/** A domain younger than this is one of the strongest signs of an attack. */
const BRAND_NEW_DAYS = 90;
const MAX_SUBJECT_CHARS = 60;
const MAX_SHARED_INDICATORS = 3;

/**
 * @param {AnalysisResult} result
 */
function originComputer(result) {
  const infra = result.infrastructure;
  const geo = infra.origin_geo;
  const clean = !infra.blacklisted && !infra.tor_exit && !infra.vpn_or_proxy && !infra.hosting_provider;
  return section(
    "The computer that sent it",
    kv([
      ["IP address", result.headers.originating_ip && html`<span class="mono strong">${result.headers.originating_ip}</span>`],
      ["Location", geo?.country && html`${flag(geo.country_code)} ${place([geo.city, geo.region, geo.country])}`],
      ["Who owns it", geo && [geo.isp, geo.org].filter(Boolean).join(" / ")],
      ["Network (ASN)", geo?.asn],
      [
        "Reputation",
        html`<span class="cluster">
          ${infra.blacklisted && chip("on a spam blocklist", "bad")}
          ${infra.tor_exit && chip("Tor exit node", "bad")}
          ${infra.vpn_or_proxy && chip("VPN / proxy", "warn")}
          ${infra.hosting_provider && chip("rented server", "warn")}
          ${clean && chip("nothing known against it", "ok")}
        </span>`,
      ],
    ]),
    { note: "Tracing the first real computer in the delivery path." },
  );
}

/**
 * @param {AnalysisResult} result
 */
function seenBefore(result) {
  const incidents = result.intel.related_incidents;
  if (incidents.length === 0) return null;
  return section(
    "Seen before",
    html`<ul class="stack">
      ${incidents.map(
        (incident) => html`<li>
          <a class="link" href="#/email/${encodeURIComponent(incident.email_id)}">${truncate(incident.subject, MAX_SUBJECT_CHARS) || incident.email_id}</a>
          <div class="hint">from ${incident.sender} · risk ${incident.risk_score} · shares ${incident.shared_indicators.slice(0, MAX_SHARED_INDICATORS).join(", ")}</div>
        </li>`,
      )}
    </ul>`,
    { note: "Earlier emails that share a server, sender or link with this one." },
  );
}

/**
 * @param {DomainIntel} domain
 */
function age(domain) {
  if (domain.age_days === null) return domain.source === "offline" ? "not checked (offline)" : "unknown";
  if (domain.age_days < BRAND_NEW_DAYS) return html`<b class="text-bad">${domain.age_days} days — brand new</b>`;
  return `${domain.age_days} days`;
}

/**
 * @param {DomainIntel} domain
 */
function domainCard(domain) {
  return html`<div class="card card--tight">
    <div class="domain-card__head"><span class="domain-card__name">${domain.domain}</span>${chip(DOMAIN_ROLE[domain.role] ?? domain.role, "teal")}</div>
    ${kv([
      ["How old", age(domain)],
      ["Registered with", domain.registrar],
      ["Can receive mail", domain.source === "offline" ? "" : domain.has_mx ? "yes" : "no — unusual for a real company"],
      ["Copycat of", domain.lookalike_of && html`<span class="text-bad strong">${domain.lookalike_of} (${domain.lookalike_technique})</span>`],
      [
        "Notes",
        html`<span class="cluster">
          ${domain.is_free_mail && chip("free mailbox (Gmail etc.)")}
          ${domain.is_disposable && chip("throwaway address", "bad")}
          ${domain.reputation.map((tag) => chip(tag, "bad"))}
        </span>`,
      ],
    ])}
  </div>`;
}

/**
 * @param {AnalysisResult} result
 */
export function domainsTab(result) {
  return html`${originComputer(result)}
    ${seenBefore(result)}
    <h3 class="domains-title">The domains involved</h3>
    <p class="hint section__note">A domain registered days ago is one of the strongest signs of an attack.</p>
    ${result.domains.length > 0
      ? html`<div class="grid grid--cards">${result.domains.map(domainCard)}</div>`
      : html`<div class="hint">No domains were checked.</div>`}`;
}
