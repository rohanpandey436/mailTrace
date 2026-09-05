// @ts-check
/** Home: the drop zone, the headline numbers and the most recent cases. */
import { api } from "../api.js";
import { useAsync } from "../hooks.js";
import { categoryOf } from "../labels.js";
import { Fragment, html } from "../react.js";
import { CasesTable } from "../ui/cases-table.js";
import { errorState, kpi, pageHead, section, skeleton } from "../ui/primitives.js";
import { Dropzone } from "../ui/upload.js";

/** @typedef {import('../types.js').DashboardStats} DashboardStats */

const RECENT_LIMIT = 8;

/**
 * @param {{ stats: DashboardStats }} props
 */
function Headline({ stats }) {
  return html`<div class="grid grid--kpi section">
    ${kpi("Emails checked", stats.total_emails, "info")}${kpi("Dangerous ones", stats.high_risk, "bad")}
    ${kpi("Linked attacks", stats.campaigns, "purple")}${kpi("Unread alerts", stats.alerts_open, "brand")}
  </div>`;
}

/**
 * @param {{ stats: DashboardStats }} props
 */
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

/**
 * @param {{ stats: DashboardStats }} props
 */
function Countries({ stats }) {
  if (stats.top_countries.length === 0) {
    return html`<div class="hint">No locations yet. Locations need internet lookups switched on.</div>`;
  }
  return html`<div class="stack">
    ${stats.top_countries.map(
      (entry) => html`<div key=${entry.country} class="dist__row"><span class="spread">${entry.country}</span><b>${entry.count}</b></div>`,
    )}
  </div>`;
}

export function DashboardView() {
  const { data, error, loading, reload } = useAsync(
    () => Promise.all([api.stats(), api.listEmails({ limit: RECENT_LIMIT })]),
    [],
  );

  const body = () => {
    if (error) return errorState(error, reload);
    if (loading || !data) {
      return html`<${Fragment}>${skeleton(1)}<div class="grid grid--recent">${skeleton(2)}${skeleton(2)}</div></>`;
    }
    const [stats, recent] = data;
    return html`<${Fragment}>
      <${Headline} stats=${stats} />
      <div class="grid grid--recent">
        <div>
          ${section(
            "Recently checked",
            recent.items.length > 0
              ? html`<${CasesTable} items=${recent.items} />`
              : html`<div class="hint">
                  Nothing here yet. Drop an email above, or try the ready-made examples in the
                  <span class="mono">samples</span> folder of the project.
                </div>`,
            { aside: html`<a class="link small" href="#/cases">See all →</a>` },
          )}
        </div>
        <div>
          ${section("What we found", html`<${Distribution} stats=${stats} />`, { note: "How the checked emails break down." })}
          ${section("Where they came from", html`<${Countries} stats=${stats} />`, { note: "Countries of the sending servers." })}
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

