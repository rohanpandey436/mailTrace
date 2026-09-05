// @ts-check
/**
 * The case list table, shared by the home page, the case list and each
 * campaign.  Rows carry the case id; `bindCaseRows` (called once at boot)
 * turns a click anywhere on a row into navigation.
 */
import { html, on } from "../dom.js";
import { formatDate } from "../format.js";
import { DECISION } from "../labels.js";
import { categoryChip, chip, riskBar } from "./primitives.js";

/** @typedef {import('../types.js').CaseSummary} CaseSummary */

/**
 * @param {CaseSummary[]} items
 */
export function casesTable(items) {
  return html`<div class="table-wrap"><table class="table">
    <thead><tr><th>Risk</th><th>What it is</th><th>Subject</th><th>From</th><th>Came from</th><th>Checked</th></tr></thead>
    <tbody>${items.map(caseRow)}</tbody>
  </table></div>`;
}

/**
 * @param {CaseSummary} item
 */
function caseRow(item) {
  const decision = item.status !== "open" ? DECISION[item.status] : null;
  return html`<tr class="table__row" data-email-id="${item.id}">
    <td>${riskBar(item.risk_score, item.severity)}</td>
    <td><div class="stack">${categoryChip(item.category)}${decision && chip(decision.label, decision.tone)}</div></td>
    <td class="col-subject">
      <div class="truncate strong" title="${item.subject}">${item.subject || html`<span class="muted">(no subject)</span>`}</div>
      <div class="hint truncate">${item.filename}</div>
    </td>
    <td class="col-sender"><div class="truncate mono" title="${item.sender}">${item.sender}</div></td>
    <td class="small">${item.originating_ip || html`<span class="muted">not traceable</span>`}<div class="muted">${item.origin_country}</div></td>
    <td class="hint nowrap">${formatDate(item.analyzed_at)}</td>
  </tr>`;
}

/**
 * Open a case when its row is clicked.  Registered once, on the document.
 * @param {Document} root
 */
export function bindCaseRows(root) {
  on(root, "click", "tr[data-email-id]", (event, row) => {
    if (event.target instanceof Element && event.target.closest("a")) return;
    const id = row.dataset.emailId;
    if (id) location.hash = `#/email/${encodeURIComponent(id)}`;
  });
}
