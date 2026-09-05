// @ts-check
/**
 * The analyst decision bar on a case (Stage 6).
 *
 * Deliberately honest wording.  These buttons write the analyst's decision to
 * the tamper-evident evidence log and collect the indicators for whoever does
 * the enforcing; MailTrace holds no mailbox credentials and never touches a
 * mail gateway, so nothing here may imply that a message was actually moved,
 * deleted or blocked anywhere.
 */
import { api, errorMessage, urls } from "../api.js";
import { $$, html, mount } from "../dom.js";
import { formatDate, plural } from "../format.js";
import { DECISION } from "../labels.js";
import { chip } from "./primitives.js";
import { toast } from "./toast.js";

/** @typedef {import('../types.js').CaseDecision} CaseDecision */
/** @typedef {import('../api.js').DecisionAction} DecisionAction */

/** @type {Array<{ action: DecisionAction, label: string, hint: string }>} */
const ACTIONS = [
  {
    action: "quarantine",
    label: "Record “quarantine”",
    hint: "Writes a quarantine decision to the evidence log and sets this case to “marked for quarantine”. It does not quarantine the email in your mailbox.",
  },
  {
    action: "block",
    label: "Record “block”",
    hint: "Writes a block decision to the evidence log and sets this case to “marked for blocking”. It does not add anything to a real block list.",
  },
];

/**
 * @param {string} emailId
 * @param {CaseDecision} decision
 */
function template(emailId, decision) {
  const state = DECISION[decision.status] ?? DECISION.open;
  const last = decision.history[decision.history.length - 1];
  return html`<div class="card card--tight cluster cluster--top cluster--loose">
    <div class="spread">
      <div class="decision__title">Your decision ${chip(state.label, state.tone)}</div>
      <p class="hint">These buttons <b>record what you decided</b> in the evidence log and gather the
        ${plural(decision.indicators.length, "indicator")} from this case so you can hand them to your mail gateway,
        firewall or SOC team. <b class="strong">MailTrace is not connected to your mail system</b>, so nothing here
        moves, deletes or blocks a message on its own.</p>
      ${last && html`<p class="hint">Last recorded by <b class="strong">${last.actor}</b> on ${formatDate(last.timestamp)}.</p>`}
    </div>
    <div class="cluster">
      ${ACTIONS.map(
        (item) => html`<button class="btn" type="button" data-decision="${item.action}" title="${item.hint}">${item.label}</button>`,
      )}
      <a class="btn" href="${urls.report(emailId, "csv")}" title="The indicators and every finding as a spreadsheet">Export indicators</a>
    </div>
  </div>`;
}

/**
 * Render the decision bar into `container` and wire its buttons.  A case the
 * server cannot report a decision for simply shows no bar.
 * @param {HTMLElement} container
 * @param {string} emailId
 */
export async function mountDecisionBar(container, emailId) {
  /** @type {CaseDecision} */
  let decision;
  try {
    decision = await api.getDecision(emailId);
  } catch {
    container.hidden = true;
    return;
  }
  render(decision);

  /** @param {CaseDecision} current */
  function render(current) {
    mount(container, template(emailId, current));
    for (const button of $$("[data-decision]", container)) {
      const action = button.dataset.decision;
      if (action === "quarantine" || action === "block") button.addEventListener("click", () => void record(action));
    }
  }

  /** @param {DecisionAction} action */
  async function record(action) {
    const buttons = /** @type {HTMLButtonElement[]} */ ($$("[data-decision]", container));
    buttons.forEach((button) => (button.disabled = true));
    try {
      render(await api.recordDecision(emailId, action));
      toast("Decision saved to the evidence log. Nothing was sent to your mail system — pass the indicators to whoever enforces.");
    } catch (error) {
      buttons.forEach((button) => (button.disabled = false));
      toast(html`Could not record that: ${errorMessage(error)}`, "error");
    }
  }
}
