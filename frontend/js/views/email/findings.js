import { plural } from "../../format.js";
import { useStore } from "../../hooks.js";
import { MODULE, PILLARS, categoryOf, plain, toneForScore } from "../../labels.js";
import { Fragment, html } from "../../react.js";
import { allFindings } from "../../state.js";
import { icon } from "../../ui/icons.js";
import { bar, chip, moreToggle, section, severityChip } from "../../ui/primitives.js";

const SHOWN_FINDINGS = 5;

function FindingRow({ finding }) {
  return html`<details class="card finding">
    <summary class="finding__summary">
      <span class="finding__sev">${severityChip(finding.severity)}</span>
      <span class="finding__main">
        <span class="finding__title">${plain(finding.title)}</span>
        ${chip(MODULE[finding.module] ?? finding.module)}
      </span>
      ${icon("chevron", "finding__caret")}
    </summary>
    <p class="finding__detail">${plain(finding.detail)}</p>
  </details>`;
}

function FindingList({ warnings }) {
  const open = useStore(allFindings);
  const rows = (list) => list.map((finding) => html`<${FindingRow} key=${finding.id} finding=${finding} />`);
  if (warnings.length <= SHOWN_FINDINGS + 1) return html`<div class="stack">${rows(warnings)}</div>`;

  const rest = warnings.slice(SHOWN_FINDINGS);
  return html`<div class="stack">
    ${rows(warnings.slice(0, SHOWN_FINDINGS))}
    ${moreToggle(open, () => allFindings.set(!open), `Show ${plural(rest.length, "more warning sign")}`, "Show fewer warning signs")}
    ${open && html`<div class="stack reveal">${rows(rest)}</div>`}
  </div>`;
}

function Agreement({ verdict }) {
  if (verdict.dual_validation_agreement) {
    return html`<${Fragment}><b class="text-ok">They agreed</b>, which raises our confidence.</>`;
  }
  const rules = categoryOf(verdict.rule_category).label;
  const model = categoryOf(verdict.ml_category).label;
  return html`<${Fragment}>
    <b class="text-warn">They disagreed</b> (the rules said ${rules}, the model said ${model}), so we deliberately lowered the
    confidence instead of hiding it.
  </>`;
}

export function findingsTab(result) {
  const warnings = result.findings.filter((finding) => finding.severity !== "info");
  const notes = result.findings.filter((finding) => finding.severity === "info");
  const verdict = result.verdict;

  const found = section(
    "Warning signs",
    warnings.length > 0
      ? html`<${FindingList} warnings=${warnings} />`
      : html`<div class="note note--info">No warning signs were found in this email.</div>`,
    {
      aside: html`<span class="hint">${plural(warnings.length, "thing")} worth knowing</span>`,
      note: "Click any row to read the detail. Worst first; the rest open with the button under the list.",
    },
  );

  const breakdown = section(
    `Why we scored it ${verdict.risk_score} out of 100`,
    html`<${Fragment}>
      <div class="stack">
        ${PILLARS.map(([key, label]) => {
          const value = Math.round(verdict.breakdown[key] ?? 0);
          return html`<div key=${key} class="pillar">
            <span class="pillar__label">${label}</span>${bar(value, toneForScore(value))}<span class="pillar__value">${value}</span>
          </div>`;
        })}
      </div>
      <p class="hint subsection">
        Two separate systems judged this email: a rule book and a trained model. <${Agreement} verdict=${verdict} />
      </p>
    </>`,
    { note: "Each area is scored out of 100, then combined by importance." },
  );

  const actions =
    verdict.recommended_actions.length > 0
      ? section(
          "What you should do",
          html`<ol class="steps">${verdict.recommended_actions.map((action, index) => html`<li key=${index}>${action}</li>`)}</ol>`,
        )
      : null;

  const background =
    notes.length > 0
      ? html`<details class="card notes-toggle">
          <summary class="more-toggle more-toggle--plain">
            <span>Show ${plural(notes.length, "background note")}</span>${icon("chevron", "more-toggle__caret")}
          </summary>
          <ul class="stack">
            ${notes.map((note) => html`<li key=${note.id}><b>${plain(note.title)}</b><div class="hint">${plain(note.detail)}</div></li>`)}
          </ul>
        </details>`
      : null;

  return html`<${Fragment}>${found}${breakdown}${actions}${background}</>`;
}
