// @ts-check
/** The case list: search, filter, page, and export the same selection as CSV. */
import { api, urls } from "../api.js";
import { plural } from "../format.js";
import { useAsync } from "../hooks.js";
import { CATEGORY } from "../labels.js";
import { Fragment, html, useState } from "../react.js";
import { session } from "../state.js";
import { CasesTable } from "../ui/cases-table.js";
import { emptyState, errorState, pageHead, skeleton } from "../ui/primitives.js";

const PAGE_SIZE = 25;

export function CasesView() {
  const [filters, setFilters] = useState(session.listFilters);
  // The range input updates as it is dragged; the query only follows on release.
  const [riskDraft, setRiskDraft] = useState(session.listFilters.minRisk);
  const [draftQuery, setDraftQuery] = useState(session.listFilters.q);

  /** @param {Partial<typeof filters>} patch */
  const apply = (patch) => {
    const next = { ...filters, ...patch, page: patch.page ?? 0 };
    session.listFilters = next;
    setFilters(next);
  };

  const query = { q: filters.q, category: filters.category, minRisk: filters.minRisk };
  const { data, error, loading, reload } = useAsync(
    () => api.listEmails({ ...query, limit: PAGE_SIZE, offset: filters.page * PAGE_SIZE }),
    [filters.q, filters.category, filters.minRisk, filters.page],
  );

  const results = () => {
    if (error) return errorState(error, reload);
    if (loading || !data) return skeleton(3);
    if (data.items.length === 0) return emptyState("Nothing matches", "Try clearing the search box or lowering the risk filter.");
    const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
    return html`<${Fragment}>
      <div class="card card--table"><${CasesTable} items=${data.items} /></div>
      <div class="pager">
        <span>${plural(data.total, "email")}</span>
        <div class="pager__controls">
          <button class="btn" type="button" disabled=${filters.page === 0} onClick=${() => apply({ page: filters.page - 1 })}>
            ← Back
          </button>
          <span>Page ${filters.page + 1} of ${pages}</span>
          <button class="btn" type="button" disabled=${filters.page + 1 >= pages} onClick=${() => apply({ page: filters.page + 1 })}>
            Next →
          </button>
        </div>
      </div>
    </>`;
  };

  return html`<${Fragment}>
    ${pageHead("Checked emails", "Every email you have run through MailTrace. Click any row to open the full report.")}
    <form
      class="card card--tight section grid grid--filters"
      onSubmit=${(/** @type {SubmitEvent} */ event) => {
        event.preventDefault();
        apply({ q: draftQuery.trim() });
      }}
    >
      <label class="field">
        Search
        <input
          class="input"
          value=${draftQuery}
          placeholder="subject, sender, IP, domain"
          autoComplete="off"
          onChange=${(/** @type {{ target: HTMLInputElement }} */ event) => setDraftQuery(event.target.value)}
        />
      </label>
      <label class="field">
        Type
        <select
          class="input"
          value=${filters.category}
          onChange=${(/** @type {{ target: HTMLSelectElement }} */ event) => apply({ category: event.target.value })}
        >
          <option value="">Show all</option>
          ${Object.entries(CATEGORY).map(([value, label]) => html`<option key=${value} value=${value}>${label.label}</option>`)}
        </select>
      </label>
      <label class="field">
        Only show risk above <b class="strong">${riskDraft}</b>
        <input
          class="range"
          type="range"
          min="0"
          max="100"
          step="5"
          value=${riskDraft}
          onChange=${(/** @type {{ target: HTMLInputElement }} */ event) => setRiskDraft(Number(event.target.value))}
          onMouseUp=${() => apply({ minRisk: riskDraft })}
          onTouchEnd=${() => apply({ minRisk: riskDraft })}
          onKeyUp=${() => apply({ minRisk: riskDraft })}
        />
      </label>
      <div class="field">
        Bulk analysis
        <a
          class="btn btn--block"
          href=${urls.exportCsv(query)}
          title="Downloads every email matching the filters on the left as a spreadsheet"
        >
          Download as CSV
        </a>
      </div>
    </form>
    ${results()}
  </>`;
}
