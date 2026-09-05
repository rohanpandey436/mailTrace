// @ts-check
/** "How it tries to trick you": pressure tactics, BEC patterns, SHAP and LIME. */
import { api } from "../../api.js";
import { $, html, mount } from "../../dom.js";
import { percent, signed } from "../../format.js";
import { BEC_PATTERN, categoryOf } from "../../labels.js";
import { bar, chip, section } from "../../ui/primitives.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').BecPattern} BecPattern */
/** @typedef {import('../../types.js').NlpAnalysis} NlpAnalysis */
/** @typedef {import('../../types.js').TokenWeight} TokenWeight */
/** @typedef {import('../../types.js').LimeReport} LimeReport */
/** @typedef {import('../../types.js').ThreatCategory} ThreatCategory */

const MAX_TERMS = 8;
const MAX_EVIDENCE = 5;
const MAX_TOP_TERMS = 6;
const MAX_WEIGHTS = 8;
/** Below this SHAP magnitudes are treated as equal, so a flat explanation still draws. */
const MIN_WEIGHT_SCALE = 0.01;
const URGENT_ABOVE = 0.5;
const PATTERN_HIGH = 0.75;
const PATTERN_MEDIUM = 0.5;

/**
 * @param {NlpAnalysis} nlp
 */
function pressureTactics(nlp) {
  /** @type {Array<[string, string[]]>} */
  const groups = [
    ["Rushing you", nlp.urgency_phrases],
    ["Scaring you", nlp.threat_terms],
    ["Talking about money", nlp.financial_terms],
    ["Asking for passwords or IDs", nlp.credential_terms],
  ];
  return section(
    "Pressure tactics",
    html`<div class="pillar section__note">
        <span class="pillar__label pillar__label--sm muted">How rushed it feels</span>
        ${bar(nlp.urgency_score * 100, nlp.urgency_score >= URGENT_ABOVE ? "bad" : "warn")}
        <span class="pillar__value">${percent(nlp.urgency_score)}</span>
      </div>
      <div class="grid grid--terms">
        ${groups.map(
          ([title, terms]) => html`<div class="terms">
            <div class="terms__label">${title}</div>
            <div class="terms__list">${terms.length > 0 ? terms.slice(0, MAX_TERMS).map((term) => chip(term, "purple")) : html`<span class="hint">nothing</span>`}</div>
          </div>`,
        )}
      </div>
      <div class="hint subsection">
        ${nlp.generic_greeting && "Opens with a generic greeting like “Dear Customer” instead of your name. "}
        ${nlp.requests_reply_not_click && "Pushes you to reply by email rather than click a link, a classic fraud move. "}
        ${nlp.word_count} words.
      </div>`,
    { note: "Scam emails almost always rush, scare or flatter you. Here is what this one does." },
  );
}

/**
 * @param {BecPattern} pattern
 */
function patternCard(pattern) {
  const tone = pattern.confidence >= PATTERN_HIGH ? "bad" : pattern.confidence >= PATTERN_MEDIUM ? "orange" : "warn";
  return html`<div class="pattern">
    <div class="pattern__head"><b>${BEC_PATTERN[pattern.pattern] ?? pattern.pattern}</b><span class="mono">${percent(pattern.confidence)}</span></div>
    ${bar(pattern.confidence * 100, tone)}
    <div class="hint subsection">Spotted: ${pattern.evidence.slice(0, MAX_EVIDENCE).join(" · ") || "—"}</div>
  </div>`;
}

/**
 * @param {NlpAnalysis} nlp
 */
function fraudPatterns(nlp) {
  return section(
    "Business fraud patterns",
    nlp.bec_patterns.length > 0
      ? html`<div class="stack">${nlp.bec_patterns.map(patternCard)}</div>`
      : html`<div class="hint">None of the common business-fraud patterns were found.</div>`,
    { note: "The four scams the problem statement asks us to catch." },
  );
}

/**
 * Signed, diverging bars: red pushes toward the predicted category, green away.
 * @param {TokenWeight[]} weights
 */
function shapChart(weights) {
  const shown = weights.slice(0, MAX_WEIGHTS);
  const scale = Math.max(MIN_WEIGHT_SCALE, ...shown.map((entry) => Math.abs(entry.weight)));
  return html`<div class="stack">
    ${shown.map((entry) => {
      const positive = entry.weight >= 0;
      const magnitude = (Math.abs(entry.weight) / scale) * 100;
      return html`<div class="shap">
        <span class="shap__token truncate" title="${entry.token}">${entry.token}</span>
        <div class="shap__scale">
          <div class="shap__neg"><i style="--value:${positive ? 0 : magnitude}"></i></div>
          <div class="shap__pos"><i style="--value:${positive ? magnitude : 0}"></i></div>
        </div>
        <span class="shap__value ${positive ? "text-bad" : "text-ok"}">${signed(entry.weight)}</span>
      </div>`;
    })}
  </div>`;
}

/**
 * @param {NlpAnalysis} nlp
 */
function modelView(nlp) {
  const probabilities = Object.entries(nlp.ml_probabilities).sort((a, b) => b[1] - a[1]);
  if (probabilities.length === 0) {
    return html`<div class="hint">The model was not available, so only the rule book was used.</div>`;
  }
  const predicted = categoryOf(nlp.ml_category).label;
  return html`<div class="probs">
      ${probabilities.map(([category, probability]) => {
        const label = categoryOf(category);
        return html`<div class="prob"><span class="prob__label">${label.label}</span>${bar(probability * 100, label.tone)}<span class="prob__value">${Math.round(probability * 100)}%</span></div>`;
      })}
    </div>
    ${nlp.shap_weights.length > 0
      ? html`<div class="subsection">
          <div class="subsection__title">Which words decided it (SHAP values)</div>
          ${shapChart(nlp.shap_weights)}
          <p class="hint subsection">Red pushes toward <b>${predicted}</b>, green pushes away from it.</p>
        </div>`
      : html`<p class="hint subsection">Words that pushed the decision: ${nlp.ml_top_terms.length > 0 ? nlp.ml_top_terms.slice(0, MAX_TOP_TERMS).map((term) => chip(term, "info")) : "—"}</p>`}
    <div id="lime" class="subsection subsection--divided">
      <div class="subsection__title">Second opinion (LIME)</div>
      <div class="skeleton"></div>
    </div>`;
}

/**
 * LIME is fitted when the case is opened, not during ingest: it costs several
 * times the rest of the analysis and changes no verdict, so the ingest pipeline
 * stays inside its budget and this arrives a moment later.
 * @param {LimeReport} report
 * @param {ThreatCategory} predicted
 */
function limeSection(report, predicted) {
  if (!report.available || report.weights.length === 0) {
    return html`<div class="subsection__title">Second opinion (LIME)</div>
      <p class="hint">Not available for this message.</p>`;
  }
  return html`<div class="subsection__title">Second opinion (LIME) — how the answer changes when words are removed</div>
    <div class="cluster">
      ${report.weights.slice(0, MAX_WEIGHTS).map((entry) => chip(`${entry.token} ${signed(entry.weight)}`, entry.weight >= 0 ? "bad" : "ok"))}
    </div>
    <p class="hint subsection">SHAP reads the model's own weights. LIME instead rewrites this email many times with words taken out, watches
      what changes, and fits a simple local model to that — here it matches the real model with R² ${report.fidelity.toFixed(2)}.
      Red pushed toward <b>${categoryOf(predicted).label}</b>, green pushed away.
      ${report.agreement_with_shap.length > 0 &&
      html`${report.agreement_with_shap.length} of its top ${report.weights.length} words also appear in the SHAP list, which is corroboration.`}</p>`;
}

/**
 * Fetch the explanation and fill in the placeholder `contentTab` left.
 * Returns a cleanup that abandons the render if the tab changes first.
 * @param {HTMLElement} panel
 * @param {AnalysisResult} result
 * @returns {() => void}
 */
export function mountExplanation(panel, result) {
  let cancelled = false;
  const box = $("#lime", panel);
  if (box) {
    api
      .getExplanation(result.id)
      .then((report) => {
        if (!cancelled) mount(box, limeSection(report, result.nlp.ml_category));
      })
      .catch(() => {
        if (!cancelled) mount(box, html`<p class="hint">The explanation could not be loaded.</p>`);
      });
  }
  return () => {
    cancelled = true;
  };
}

/**
 * @param {AnalysisResult} result
 */
export function contentTab(result) {
  const nlp = result.nlp;
  return html`<div class="grid grid--2">
    ${pressureTactics(nlp)}
    ${fraudPatterns(nlp)}
    ${section("What the trained model thinks", modelView(nlp), { note: "A model trained on hundreds of example emails scores every category." })}
    ${section("The message itself", html`<pre class="body-text mono">${result.email.text_body || "(empty)"}</pre>`)}
  </div>`;
}
