// @ts-check
/**
 * Home: the drop zone, the headline numbers and the most recent cases.
 */
import { api } from "../api.js";
import { html, mount, must } from "../dom.js";
import { categoryOf } from "../labels.js";
import { casesTable } from "../ui/cases-table.js";
import { kpi, pageHead, section, skeleton } from "../ui/primitives.js";
import { bindUpload, dropzone } from "../ui/upload.js";

/** @typedef {import('../types.js').DashboardStats} DashboardStats */

const RECENT_LIMIT = 8;

/**
 * @param {DashboardStats} stats
 */
function headline(stats) {
  return html`<div class="grid grid--kpi section">
    ${kpi("Emails checked", stats.total_emails, "info")}
    ${kpi("Dangerous ones", stats.high_risk, "bad")}
    ${kpi("Linked attacks", stats.campaigns, "purple")}
    ${kpi("Unread alerts", stats.alerts_open, "brand")}
  </div>`;
}

/**
 * @param {DashboardStats} stats
 */
function distribution(stats) {
  const total = stats.total_emails;
  const categories = Object.entries(stats.by_category).filter(([, count]) => count > 0);
  if (total === 0 || categories.length === 0) return html`<div class="hint">Nothing checked yet.</div>`;
  return html`<div class="dist__bar">
      ${categories.map(([category, count]) => {
        const label = categoryOf(category);
        return html`<div class="dist__seg tone-${label.tone}" style="--value:${(count / total) * 100}" title="${label.label}: ${count}"></div>`;
      })}
    </div>
    <div class="stack">
      ${categories.map(([category, count]) => {
        const label = categoryOf(category);
        return html`<div class="dist__row"><span class="dot tone-${label.tone}"></span><span class="spread">${label.label}</span><b>${count}</b></div>`;
      })}
    </div>`;
}

/**
 * @param {DashboardStats} stats
 */
function countries(stats) {
  if (stats.top_countries.length === 0) {
    return html`<div class="hint">No locations yet. Locations need internet lookups switched on.</div>`;
  }
  return html`<div class="stack">
    ${stats.top_countries.map((entry) => html`<div class="dist__row"><span class="spread">${entry.country}</span><b>${entry.count}</b></div>`)}
  </div>`;
}

/** @type {import('../router.js').View} */
export async function dashboardView(container) {
  mount(
    container,
    html`${pageHead(
        "Check an email",
        "Drop in a saved email and MailTrace reads its hidden headers to work out who really sent it, where in the world it came from, and whether it is trying to trick you.",
      )}
      ${dropzone()}
      <div id="stats">${skeleton(1)}</div>
      <div class="grid grid--recent"><div id="recent">${skeleton(2)}</div><div id="side">${skeleton(2)}</div></div>`,
  );
  bindUpload(must("#dropzone", container), /** @type {HTMLInputElement} */ (must("#file-input")));

  const [stats, recent] = await Promise.all([api.stats(), api.listEmails({ limit: RECENT_LIMIT })]);
  mount(must("#stats", container), headline(stats));
  mount(
    must("#side", container),
    html`${section("What we found", distribution(stats), { note: "How the checked emails break down." })}
      ${section("Where they came from", countries(stats), { note: "Countries of the sending servers." })}`,
  );
  mount(
    must("#recent", container),
    section(
      "Recently checked",
      recent.items.length > 0
        ? casesTable(recent.items)
        : html`<div class="hint">Nothing here yet. Drop an email above, or try the ready-made examples in the
            <span class="mono">samples</span> folder of the project.</div>`,
      { aside: html`<a class="link small" href="#/cases">See all →</a>` },
    ),
  );
}
