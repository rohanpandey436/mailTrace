import { formatDate } from "../format.js";
import { DECISION } from "../labels.js";
import { html } from "../react.js";
import { navigate } from "../router.js";
import { categoryChip, chip, riskBar } from "./primitives.js";

export function CasesTable({ items }) {
  return html`<div class="cases">
    <table class="table table--cases" role="table">
      <thead role="rowgroup">
        <tr role="row">
          <th class="col-risk" role="columnheader" scope="col">Risk</th>
          <th class="col-type" role="columnheader" scope="col">What it is</th>
          <th class="col-subject" role="columnheader" scope="col">Subject</th>
          <th class="col-sender" role="columnheader" scope="col">From</th>
          <th class="col-origin" role="columnheader" scope="col">Came from</th>
          <th class="col-when" role="columnheader" scope="col">Checked</th>
        </tr>
      </thead>
      <tbody role="rowgroup">
        ${items.map((item) => html`<${CaseRow} key=${item.id} item=${item} />`)}
      </tbody>
    </table>
  </div>`;
}

function CaseRow({ item }) {
  const decision = item.status !== "open" ? DECISION[item.status] : null;
  const address = `#/email/${encodeURIComponent(item.id)}`;
  const open = (event) => {
    if (event.target instanceof Element && event.target.closest("a")) return;
    navigate(address);
  };
  return html`<tr class="table__row" role="row" onClick=${open}>
    <td class="col-risk" role="cell">${riskBar(item.risk_score, item.severity)}</td>
    <td class="col-type" role="cell">
      <div class="stack">${categoryChip(item.category)}${decision && chip(decision.label, decision.tone)}</div>
    </td>
    <td class="col-subject" role="cell">
      <a class="case__subject" href=${address} title=${item.subject}>${item.subject || "(no subject)"}</a>
      <div class="hint truncate case__file">${item.filename}</div>
      <div class="hint truncate mono case__from">${item.sender}</div>
    </td>
    <td class="col-sender" role="cell"><div class="truncate mono" title=${item.sender}>${item.sender}</div></td>
    <td class="col-origin small" role="cell">
      <span>${item.originating_ip || html`<span class="muted">not traceable</span>`}</span>
      <span class="muted case__country">${item.origin_country}</span>
    </td>
    <td class="col-when hint" role="cell">${formatDate(item.analyzed_at)}</td>
  </tr>`;
}
