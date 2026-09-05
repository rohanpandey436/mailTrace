// @ts-check
/** "What we found": findings, the five-pillar breakdown, actions, background notes. */
import { html } from "../../dom.js";
import { plural } from "../../format.js";
import { MODULE, PILLARS, categoryOf, toneForScore } from "../../labels.js";
import { bar, chip, section, severityChip } from "../../ui/primitives.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').Finding} Finding */
/** @typedef {import('../../types.js').Verdict} Verdict */

/**
 * @param {Finding} finding
 */
function findingRow(finding) {
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
 * @param {Finding[]} warnings
 */
function found(warnings) {
  return section(
    "What we found",
    warnings.length > 0
      ? html`<div class="stack">${warnings.map(findingRow)}</div>`
      : html`<div class="note note--info">No warning signs were found in this email.</div>`,
    {
      aside: html`<span class="hint">${plural(warnings.length, "thing")} worth knowing</span>`,
      note: "Click any row to read the detail. Worst first.",
    },
  );
}

/**
 * @param {Verdict} verdict
 */
function agreement(verdict) {
  if (verdict.dual_validation_agreement) {
    return html`<b class="text-ok">They agreed</b>, which raises our confidence.`;
  }
  return html`<b class="text-warn">They disagreed</b> (the rules said ${categoryOf(verdict.rule_category).label}, the model said
    ${categoryOf(verdict.ml_category).label}), so we deliberately lowered the confidence instead of hiding it.`;
}

/**
 * The five Stage 4 pillars, in plain English with the spec name in brackets.
 * @param {Verdict} verdict
 */
function scoreBreakdown(verdict) {
  return section(
    `Why we scored it ${verdict.risk_score} out of 100`,
    html`<div class="stack">
        ${PILLARS.map(([key, label]) => {
          const value = Math.round(verdict.breakdown[key] ?? 0);
          return html`<div class="pillar"><span class="pillar__label">${label}</span>${bar(value, toneForScore(value))}<span class="pillar__value">${value}</span></div>`;
        })}
      </div>
      <p class="hint subsection">Two separate systems judged this email: a rule book and a trained model. ${agreement(verdict)}</p>`,
    { note: "Each area is scored out of 100, then combined by importance." },
  );
}

/**
 * @param {Verdict} verdict
 */
function actions(verdict) {
  if (verdict.recommended_actions.length === 0) return null;
  return section("What you should do", html`<ol class="steps">${verdict.recommended_actions.map((action) => html`<li>${action}</li>`)}</ol>`);
}

/**
 * @param {Finding[]} notes
 */
function background(notes) {
  if (notes.length === 0) return null;
  return html`<details class="card card--tight notes-toggle">
    <summary>Show ${plural(notes.length, "background note")} ▾</summary>
    <ul class="stack">${notes.map((note) => html`<li><b>${note.title}</b><div class="hint">${note.detail}</div></li>`)}</ul>
  </details>`;
}

/**
 * @param {AnalysisResult} result
 */
export function findingsTab(result) {
  const warnings = result.findings.filter((finding) => finding.severity !== "info");
  const notes = result.findings.filter((finding) => finding.severity === "info");
  return html`${found(warnings)}${scoreBreakdown(result.verdict)}${actions(result.verdict)}${background(notes)}`;
}
