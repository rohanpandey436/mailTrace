import { flag, place, truncate } from "../../format.js";
import { DOMAIN_ROLE, LOOKALIKE, REPUTATION, sharedNouns } from "../../labels.js";
import { Fragment, html } from "../../react.js";
import { Explained, chip, kv, section } from "../../ui/primitives.js";

const BRAND_NEW_DAYS = 90;
const MAX_SUBJECT_CHARS = 60;
const MAX_SHARED_INDICATORS = 3;

function originComputer(result) {
  const infra = result.infrastructure;
  const geo = infra.origin_geo;
  const clean = !infra.blacklisted && !infra.tor_exit && !infra.vpn_or_proxy && !infra.hosting_provider;
  return section(
    "The computer that sent it",
    kv([
      ["IP address", result.headers.originating_ip && html`<span class="mono strong">${result.headers.originating_ip}</span>`],
      ["Location", geo?.country && html`<${Fragment}>${flag(geo.country_code)} ${place([geo.city, geo.region, geo.country])}</>`],
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

function seenLine(incident) {
  const shared = sharedNouns(incident.shared_indicators.slice(0, MAX_SHARED_INDICATORS));
  return `from ${incident.sender} · risk ${incident.risk_score}${shared ? ` · same ${shared}` : ""}`;
}

function seenBefore(result) {
  const incidents = result.intel.related_incidents;
  if (incidents.length === 0) return null;
  return section(
    "Seen before",
    html`<ul class="stack">
      ${incidents.map(
        (incident) => html`<li key=${incident.email_id}>
          <a class="link" href=${`#/email/${encodeURIComponent(incident.email_id)}`}>
            ${truncate(incident.subject, MAX_SUBJECT_CHARS) || incident.email_id}
          </a>
          <div class="hint">${seenLine(incident)}</div>
        </li>`,
      )}
    </ul>`,
    { note: "Earlier emails that share a server, sender or link with this one." },
  );
}

function age(domain) {
  if (domain.age_days === null) return domain.source === "offline" ? "not checked (offline)" : "unknown";
  if (domain.age_days < BRAND_NEW_DAYS) return html`<b class="text-bad">${domain.age_days} days, brand new</b>`;
  return `${domain.age_days} days`;
}

function DomainCard({ domain }) {
  const tags = domain.reputation.filter((tag) => !(tag === "disposable" && domain.is_disposable));
  const noted = domain.is_free_mail || domain.is_disposable || tags.length > 0;
  return html`<div class="card card--tight">
    <div class="domain-card__head">
      <span class="domain-card__name">${domain.domain}</span>${chip(DOMAIN_ROLE[domain.role] ?? domain.role, "teal")}
    </div>
    ${kv([
      ["How old", age(domain)],
      ["Registered with", domain.registrar],
      ["Can receive mail", domain.source === "offline" ? "" : domain.has_mx ? "yes" : "no, unusual for a real company"],
      domain.lookalike_of && [
        "Copycat of",
        html`<${Fragment}>
          <span class="text-bad strong">${domain.lookalike_of}</span>${" "}
          <span class="hint">(${LOOKALIKE[domain.lookalike_technique] ?? domain.lookalike_technique})</span>
        </>`,
      ],
      noted && [
        "Notes",
        html`<span class="cluster">
          ${domain.is_free_mail && chip("free mailbox service")}
          ${domain.is_disposable && chip("throwaway address", "bad")}
          ${tags.map((tag, index) => chip(REPUTATION[tag] ?? tag, "bad", { key: index }))}
        </span>`,
      ],
    ])}
  </div>`;
}

export function domainsTab(result) {
  return html`<${Fragment}>
    ${originComputer(result)} ${seenBefore(result)}
    <${Explained}
      title="The domains involved"
      note="A domain registered days ago is one of the strongest signs of an attack."
      titleClass="domains-title"
    />
    ${result.domains.length > 0
      ? html`<div class="grid grid--cards">
          ${result.domains.map((domain, index) => html`<${DomainCard} key=${domain.domain + index} domain=${domain} />`)}
        </div>`
      : html`<div class="hint">No domains were checked.</div>`}
  </>`;
}
