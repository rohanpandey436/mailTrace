import { api } from "../api.js";
import { useAsync, usePageTitle } from "../hooks.js";
import { categoryOf } from "../labels.js";
import { Fragment, html } from "../react.js";
import { CasesTable } from "../ui/cases-table.js";
import { errorState, kpi, loadingState, pageHead, section, skeleton } from "../ui/primitives.js";
import { OriginList, ThreatMap } from "../ui/threat-map.js";
import { Dropzone } from "../ui/upload.js";

const RECENT_LIMIT = 8;

function Headline({ stats }) {
  return html`<div class="grid grid--kpi section">
    ${kpi("Emails checked", stats.total_emails, "ink")}${kpi("Dangerous ones", stats.high_risk, stats.high_risk > 0 ? "bad" : "ink")}
    ${kpi("Linked attacks", stats.campaigns, "ink")}${kpi("Unread alerts", stats.alerts_open, "ink")}
  </div>`;
}

function Distribution({ stats }) {
  const total = stats.total_emails;
  const categories = Object.entries(stats.by_category).filter(([, count]) => count > 0);
  if (total === 0 || categories.length === 0) return html`<div class="hint">Nothing checked yet.</div>`;
  return html`<${Fragment}>
    <div class="dist__bar">
      ${categories.map(([category, count]) => {
        const label = categoryOf(category);
        return html`<div
          key=${category}
          class=${`dist__seg tone-${label.tone}`}
          style=${{ "--value": String((count / total) * 100) }}
          title=${`${label.label}: ${count}`}
        ></div>`;
      })}
    </div>
    <div class="stack">
      ${categories.map(([category, count]) => {
        const label = categoryOf(category);
        return html`<div key=${category} class="dist__row">
          <span class=${`dot tone-${label.tone}`}></span><span class="spread">${label.label}</span><b>${count}</b>
        </div>`;
      })}
    </div>
  </>`;
}

function Origins({ origins }) {
  if (origins.length === 0) {
    return html`<div class="hint">No locations yet. Locations need internet lookups switched on.</div>`;
  }
  return html`<div class="threat"><${ThreatMap} origins=${origins} /><${OriginList} origins=${origins} /></div>`;
}

export function DashboardView() {
  usePageTitle("Check an email");
  const { data, error, loading, slow, reload } = useAsync(
    () => Promise.all([api.stats(), api.listEmails({ limit: RECENT_LIMIT }), api.origins().catch(() => [])]),
    [],
  );

  const body = () => {
    if (error) return errorState(error, reload);
    if (loading || !data) {
      return html`<${Fragment}>${skeleton(1)}<div class="grid grid--recent">${skeleton(2)}${loadingState(2, slow)}</div></>`;
    }
    const [stats, recent, origins] = data;
    return html`<${Fragment}>
      <${Headline} stats=${stats} />
      ${section("Where the emails came from", html`<${Origins} origins=${origins} />`, {
        note: "Each circle is a computer that sent one of the checked emails. Bigger means more emails, and the colour shows the highest risk seen from it.",
      })}
      <div class="grid grid--recent">
        <div>
          ${section(
            "Recently checked",
            recent.items.length > 0
              ? html`<${CasesTable} items=${recent.items} />`
              : html`<div class="hint">Nothing here yet. Drop an email above, or try one of the samples.</div>`,
            { aside: html`<a class="link small" href="#/cases">See all →</a>` },
          )}
        </div>
        <div>
          ${section("What we found", html`<${Distribution} stats=${stats} />`, { note: "How the checked emails break down." })}
        </div>
      </div>
    </>`;
  };

  return html`<${Fragment}>
    ${pageHead(
      "Check an email",
      "Drop in a saved email and MailTrace reads its hidden headers to work out who really sent it, where in the world it came from, and whether it is trying to trick you.",
    )}
    <${Dropzone} />
    ${body()}
  </>`;
}
