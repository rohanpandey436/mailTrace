import { clampPercent } from "../format.js";
import { categoryOf, severityOf } from "../labels.js";
import { Fragment, html } from "../react.js";

const GAUGE_ARC_LENGTH = Math.PI * 80;

export function chip(text, tone = "neutral", { mono = false, title = "", key = undefined } = {}) {
  return html`<span key=${key} class="chip tone-${tone}${mono ? " chip--mono" : ""}" title=${title || undefined}>${text}</span>`;
}

export function categoryChip(category) {
  const label = categoryOf(category);
  return chip(label.label, label.tone);
}

export function severityChip(severity) {
  const label = severityOf(severity);
  return chip(label.label, label.tone);
}

export function check(label, value, outcome, why) {
  const tone = outcome === true ? "ok" : outcome === false ? "bad" : "neutral";
  const mark = outcome === true ? "✓" : outcome === false ? "✕" : "–";
  return html`<span class="chip tone-${tone}" title=${why}>${mark} ${label} <span class="chip__value">${value}</span></span>`;
}

export function bar(value, tone) {
  return html`<div class="bar tone-${tone}"><div class="bar__fill" style=${{ "--value": String(clampPercent(value)) }}></div></div>`;
}

export function riskBar(score, severity) {
  return html`<div class="risk">${bar(score, severityOf(severity).tone)}<span class="risk__score">${score}</span></div>`;
}

export function gauge(score, severity) {
  const filled = (GAUGE_ARC_LENGTH * clampPercent(score)) / 100;
  return html`<svg class="gauge tone-${severityOf(severity).tone}" viewBox="0 0 200 120" role="img" aria-label=${`Risk ${score} out of 100`}>
    <path class="gauge__track" d="M 20 100 A 80 80 0 0 1 180 100" />
    <path class="gauge__value" d="M 20 100 A 80 80 0 0 1 180 100" stroke-dasharray=${`${filled} ${GAUGE_ARC_LENGTH}`} />
    <text class="gauge__score" x="100" y="90" text-anchor="middle">${score}</text>
    <text class="gauge__caption" x="100" y="112" text-anchor="middle">RISK OUT OF 100</text>
  </svg>`;
}

export function section(title, body, { aside = null, note = "" } = {}) {
  return html`<section class="card card--pad section">
    <div class="section__head"><h3 class="section__title">${title}</h3>${aside}</div>
    ${note ? html`<p class="hint section__note">${note}</p>` : html`<div class="section__spacer"></div>`}
    ${body}
  </section>`;
}

export function pageHead(title, intro) {
  return html`<div class="page-head"><h1 class="page-title">${title}</h1><p class="page-intro">${intro}</p></div>`;
}

export function kpi(label, value, tone) {
  return html`<div class="card card--tight kpi tone-${tone}"><div class="kpi__label">${label}</div><div class="kpi__value">${value ?? 0}</div></div>`;
}

export function kv(pairs) {
  return html`<dl class="kv">${pairs.map(
    ([key, value], index) =>
      html`<${Fragment} key=${key + index}
        ><dt>${key}</dt>
        <dd>${value === null || value === undefined || value === "" ? html`<span class="muted">—</span>` : value}</dd></${Fragment}
      >`,
  )}</dl>`;
}

export function skeleton(count = 3) {
  return html`${Array.from({ length: count }, (_, index) => html`<div key=${index} class="skeleton"></div>`)}`;
}

export function emptyState(title, hint = "") {
  return html`<div class="card empty"><div class="empty__title">${title}</div><div class="hint empty__hint">${hint}</div></div>`;
}

export function errorState(message, onRetry) {
  return html`<div class="card empty">
    <div class="empty__title">Could not load this page</div>
    <div class="hint empty__hint">${message}</div>
    ${onRetry && html`<button class="btn" type="button" onClick=${onRetry}>Try again</button>`}
  </div>`;
}
