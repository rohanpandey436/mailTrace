import { formatDate } from "../format.js";
import { DECISION } from "../labels.js";
import { html } from "../react.js";
import { navigate } from "../router.js";
import { categoryChip, chip, riskBar } from "./primitives.js";

export function CasesTable({ items }) {
  return html`<div class="table-wrap"><table class="table">
    <thead><tr><th>Risk</th><th>What it is</th><th>Subject</th><th>From</th><th>Came from</th><th>Checked</th></tr></thead>
    <tbody>${items.map((item) => html`<${CaseRow} key=${item.id} item=${item} />`)}</tbody>
  </table></div>`;
}

function CaseRow({ item }) {
  const decision = item.status !== "open" ? DECISION[item.status] : null;
  const open = (event) => {
    if (event.target instanceof Element && event.target.closest("a")) return;
    navigate(`#/email/${encodeURIComponent(item.id)}`);
  };
  return html`<tr class="table__row" onClick=${open}>
    <td>${riskBar(item.risk_score, item.severity)}</td>
    <td><div class="stack">${categoryChip(item.category)}${decision && chip(decision.label, decision.tone)}</div></td>
    <td class="col-subject">
      <div class="truncate strong" title=${item.subject}>${item.subject || html`<span class="muted">(no subject)</span>`}</div>
      <div class="hint truncate">${item.filename}</div>
    </td>
    <td class="col-sender"><div class="truncate mono" title=${item.sender}>${item.sender}</div></td>
    <td class="small">
      ${item.originating_ip || html`<span class="muted">not traceable</span>`}
      <div class="muted">${item.origin_country}</div>
    </td>
    <td class="hint nowrap">${formatDate(item.analyzed_at)}</td>
  </tr>`;
}
