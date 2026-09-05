// @ts-check
/**
 * Small presentational pieces shared by every view: chips, bars, the gauge,
 * sections and the loading / empty / error states.  Each returns markup and
 * holds no state.
 */
import { attr, html } from "../dom.js";
import { clampPercent } from "../format.js";
import { categoryOf, severityOf } from "../labels.js";

/** @typedef {import('../dom.js').Renderable} Renderable */
/** @typedef {import('../labels.js').Tone} Tone */

const GAUGE_ARC_LENGTH = Math.PI * 80;

/**
 * @param {Renderable} text
 * @param {Tone} [tone]
 * @param {{ mono?: boolean, title?: string }} [options]
 */
export function chip(text, tone = "neutral", { mono = false, title = "" } = {}) {
  return html`<span class="chip tone-${tone}${mono ? " chip--mono" : ""}"${attr("title", title)}>${text}</span>`;
}

/**
 * The threat category as a coloured chip.
 * @param {string | null | undefined} category
 */
export function categoryChip(category) {
  const label = categoryOf(category);
  return chip(label.label, label.tone);
}

/**
 * @param {string | null | undefined} severity
 */
export function severityChip(severity) {
  const label = severityOf(severity);
  return chip(label.label, label.tone);
}

/**
 * A pass / fail / unknown check with its raw value, e.g. "✓ Allowed to send pass".
 * @param {string} label
 * @param {string} value
 * @param {boolean | null} outcome
 * @param {string} why shown on hover
 */
export function check(label, value, outcome, why) {
  const tone = outcome === true ? "ok" : outcome === false ? "bad" : "neutral";
  const mark = outcome === true ? "✓" : outcome === false ? "✕" : "–";
  return html`<span class="chip tone-${tone}" title="${why}">${mark} ${label} <span class="chip__value">${value}</span></span>`;
}

/**
 * A horizontal 0-100 bar.
 * @param {number} value
 * @param {Tone} tone
 */
export function bar(value, tone) {
  return html`<div class="bar tone-${tone}"><div class="bar__fill" style="--value:${clampPercent(value)}"></div></div>`;
}

/**
 * A short bar with the score beside it, as used in tables.
 * @param {number} score
 * @param {string} severity
 */
export function riskBar(score, severity) {
  return html`<div class="risk">${bar(score, severityOf(severity).tone)}<span class="risk__score">${score}</span></div>`;
}

/**
 * The half-circle risk gauge.
 * @param {number} score
 * @param {string} severity
 */
export function gauge(score, severity) {
  const filled = (GAUGE_ARC_LENGTH * clampPercent(score)) / 100;
  return html`<svg class="gauge tone-${severityOf(severity).tone}" viewBox="0 0 200 120" role="img" aria-label="Risk ${score} out of 100">
    <path class="gauge__track" d="M 20 100 A 80 80 0 0 1 180 100" />
    <path class="gauge__value" d="M 20 100 A 80 80 0 0 1 180 100" stroke-dasharray="${filled} ${GAUGE_ARC_LENGTH}" />
    <text class="gauge__score" x="100" y="90" text-anchor="middle">${score}</text>
    <text class="gauge__caption" x="100" y="112" text-anchor="middle">RISK OUT OF 100</text>
  </svg>`;
}

/**
 * A titled card.
 * @param {string} title
 * @param {Renderable} body
 * @param {{ aside?: Renderable, note?: string }} [options] `aside` sits right of the title, `note` explains the section
 */
export function section(title, body, { aside = null, note = "" } = {}) {
  return html`<section class="card card--pad section">
    <div class="section__head"><h3 class="section__title">${title}</h3>${aside}</div>
    ${note ? html`<p class="hint section__note">${note}</p>` : html`<div class="section__spacer"></div>`}
    ${body}
  </section>`;
}

/**
 * @param {string} title
 * @param {string} intro
 */
export function pageHead(title, intro) {
  return html`<div class="page-head"><h1 class="page-title">${title}</h1><p class="page-intro">${intro}</p></div>`;
}

/**
 * @param {string} label
 * @param {number | null | undefined} value
 * @param {Tone} tone
 */
export function kpi(label, value, tone) {
  return html`<div class="card card--tight kpi tone-${tone}"><div class="kpi__label">${label}</div><div class="kpi__value">${value ?? 0}</div></div>`;
}

/**
 * A definition list.  An empty value renders as a dash.
 * @param {Array<[string, Renderable]>} pairs
 */
export function kv(pairs) {
  return html`<dl class="kv">${pairs.map(
    ([key, value]) => html`<dt>${key}</dt><dd>${value === null || value === undefined || value === "" ? html`<span class="muted">—</span>` : value}</dd>`,
  )}</dl>`;
}

/**
 * Placeholder blocks while data loads.
 * @param {number} [count]
 */
export function skeleton(count = 3) {
  return html`${Array.from({ length: count }, () => html`<div class="skeleton"></div>`)}`;
}

/**
 * @param {string} title
 * @param {Renderable} [hint]
 */
export function emptyState(title, hint = "") {
  return html`<div class="card empty"><div class="empty__title">${title}</div><div class="hint empty__hint">${hint}</div></div>`;
}

/**
 * @param {string} message
 */
export function errorState(message) {
  return html`<div class="card empty">
    <div class="empty__title">Could not load this page</div>
    <div class="hint empty__hint">${message}</div>
    <button class="btn" type="button" data-retry>Try again</button>
  </div>`;
}
