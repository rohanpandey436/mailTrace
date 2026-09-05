// @ts-check
/** "What we found": findings, the five-pillar breakdown, actions, background notes. */
import { plural } from "../../format.js";
import { MODULE, PILLARS, categoryOf, toneForScore } from "../../labels.js";
import { Fragment, html } from "../../react.js";
import { bar, chip, section, severityChip } from "../../ui/primitives.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').Finding} Finding */
/** @typedef {import('../../types.js').Verdict} Verdict */

/**
 * @param {{ finding: Finding }} props
 */
function FindingRow({ finding }) {
  return html`<details class="card finding">
    <summary class="finding__summary">
      <span class="finding__sev">${severityChip(finding.severity)}</span>
      <span class="finding__title">${finding.title}</span>
      ${chip(MODULE[finding.module] ?? finding.module)}
      <span class="finding__caret">▾</span>
    </summary>
    <p class="finding__detail">${finding.detail}</p>
  </details>`;
}

/**
 * @param {{ verdict: Verdict }} props
 */
function Agreement({ verdict }) {
  if (verdict.dual_validation_agreement) {
    return html`<${Fragment}><b class="text-ok">They agreed</b>, which raises our confidence.</>`;
  }
  return html`<${Fragment}>
    <b class="text-warn">They disagreed</b> (the rules said ${categoryOf(verdict.rule_category).label}, the model said
    ${categoryOf(verdict.ml_category).label}), so we deliberately lowered the confidence instead of hiding it.
  </>`;
}

/**
 * @param {AnalysisResult} result
 */
export function findingsTab(result) {
  const warnings = result.findings.filter((finding) => finding.severity !== "info");
  const notes = result.findings.filter((finding) => finding.severity === "info");
  const verdict = result.verdict;

  const found = section(
    "What we found",
    warnings.length > 0
      ? html`<div class="stack">${warnings.map((finding) => html`<${FindingRow} key=${finding.id} finding=${finding} />`)}</div>`
      : html`<div class="note note--info">No warning signs were found in this email.</div>`,
    {
      aside: html`<span class="hint">${plural(warnings.length, "thing")} worth knowing</span>`,
      note: "Click any row to read the detail. Worst first.",
    },
  );

  // The five Stage 4 pillars, in plain English with the spec name in brackets.
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
      ? html`<details class="card card--tight notes-toggle">
          <summary>Show ${plural(notes.length, "background note")} ▾</summary>
          <ul class="stack">
            ${notes.map((note) => html`<li key=${note.id}><b>${note.title}</b><div class="hint">${note.detail}</div></li>`)}
          </ul>
        </details>`
      : null;

  return html`<${Fragment}>${found}${breakdown}${actions}${background}</>`;
}
