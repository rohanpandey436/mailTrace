// @ts-check
/** The case list: search, filter, page, and export the same selection as CSV. */
import { api, errorMessage, urls } from "../api.js";
import { $, attr, html, mount, must } from "../dom.js";
import { plural } from "../format.js";
import { CATEGORY } from "../labels.js";
import { session } from "../state.js";
import { casesTable } from "../ui/cases-table.js";
import { emptyState, errorState, pageHead, skeleton } from "../ui/primitives.js";

const PAGE_SIZE = 25;

/** @type {import('../router.js').View} */
export async function casesView(container) {
  const filters = session.listFilters;
  mount(
    container,
    html`${pageHead("Checked emails", "Every email you have run through MailTrace. Click any row to open the full report.")}
      <form class="card card--tight section grid grid--filters" id="filters">
        <label class="field">Search<input id="f-q" class="input" value="${filters.q}" placeholder="subject, sender, IP, domain" autocomplete="off"></label>
        <label class="field">Type
          <select id="f-cat" class="input">
            <option value="">Show all</option>
            ${Object.entries(CATEGORY).map(
              ([value, label]) => html`<option value="${value}"${attr("selected", filters.category === value)}>${label.label}</option>`,
            )}
          </select>
        </label>
        <label class="field">Only show risk above <b class="strong" id="f-risk-val">${filters.minRisk}</b>
          <input id="f-risk" class="range" type="range" min="0" max="100" step="5" value="${filters.minRisk}">
        </label>
        <div class="field">Bulk analysis
          <a class="btn btn--block" id="export-csv" href="${urls.exportCsv(filters)}"
             title="Downloads every email matching the filters on the left as a spreadsheet">Download as CSV</a>
        </div>
      </form>
      <div id="cases-body">${skeleton(3)}</div>`,
  );

  const search = /** @type {HTMLInputElement} */ (must("#f-q", container));
  const category = /** @type {HTMLSelectElement} */ (must("#f-cat", container));
  const risk = /** @type {HTMLInputElement} */ (must("#f-risk", container));
  const riskLabel = must("#f-risk-val", container);
  const exportLink = /** @type {HTMLAnchorElement} */ (must("#export-csv", container));
  const body = must("#cases-body", container);

  const apply = () => {
    filters.q = search.value.trim();
    filters.category = category.value;
    filters.minRisk = Number(risk.value);
    filters.page = 0;
    void load();
  };
  must("#filters", container).addEventListener("submit", (event) => {
    event.preventDefault();
    apply();
  });
  category.addEventListener("change", apply);
  risk.addEventListener("input", () => {
    riskLabel.textContent = risk.value;
  });
  risk.addEventListener("change", apply);

  async function load() {
    const query = { q: filters.q, category: filters.category, minRisk: filters.minRisk };
    // The CSV export takes the same filters as the listing, minus the paging.
    exportLink.href = urls.exportCsv(query);
    mount(body, skeleton(3));
    try {
      const data = await api.listEmails({ ...query, limit: PAGE_SIZE, offset: filters.page * PAGE_SIZE });
      const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
      if (data.items.length === 0) {
        mount(body, emptyState("Nothing matches", "Try clearing the search box or lowering the risk filter."));
        return;
      }
      mount(
        body,
        html`<div class="card card--table">${casesTable(data.items)}</div>
          <div class="pager">
            <span>${plural(data.total, "email")}</span>
            <div class="pager__controls">
              <button class="btn" type="button" id="pg-prev"${attr("disabled", filters.page === 0)}>← Back</button>
              <span>Page ${filters.page + 1} of ${pages}</span>
              <button class="btn" type="button" id="pg-next"${attr("disabled", filters.page + 1 >= pages)}>Next →</button>
            </div>
          </div>`,
      );
      $("#pg-prev", body)?.addEventListener("click", () => {
        filters.page -= 1;
        void load();
      });
      $("#pg-next", body)?.addEventListener("click", () => {
        filters.page += 1;
        void load();
      });
    } catch (error) {
      mount(body, errorState(errorMessage(error)));
      $("[data-retry]", body)?.addEventListener("click", () => void load());
    }
  }
  await load();
}
