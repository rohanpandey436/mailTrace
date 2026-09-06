// @ts-check
import { api, errorMessage, urls } from "../api.js";
import { formatDate, plural } from "../format.js";
import { DECISION } from "../labels.js";
import { html, useEffect, useState } from "../react.js";
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
 * @param {{ emailId: string }} props
 */
export function DecisionBar({ emailId }) {
  const [decision, setDecision] = useState(/** @type {CaseDecision | null} */ (null));
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .getDecision(emailId)
      .then((current) => {
        if (!cancelled) setDecision(current);
      })
      .catch(() => {
        // A case the server cannot report a decision for simply shows no bar.
      });
    return () => {
      cancelled = true;
    };
  }, [emailId]);

  if (!decision) return null;

  const state = DECISION[decision.status] ?? DECISION.open;
  const last = decision.history[decision.history.length - 1];

  /** @param {DecisionAction} action */
  async function record(action) {
    setBusy(true);
    try {
      setDecision(await api.recordDecision(emailId, action));
      toast("Decision saved to the evidence log. Nothing was sent to your mail system — pass the indicators to whoever enforces.");
    } catch (error) {
      toast(html`Could not record that: ${errorMessage(error)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  return html`<div class="card card--tight cluster cluster--top cluster--loose">
    <div class="spread">
      <div class="decision__title">Your decision ${chip(state.label, state.tone)}</div>
      <p class="hint">
        These buttons <b>record what you decided</b> in the evidence log and gather the
        ${plural(decision.indicators.length, "indicator")} from this case so you can hand them to your mail gateway, firewall or SOC
        team. <b class="strong">MailTrace is not connected to your mail system</b>, so nothing here moves, deletes or blocks a message
        on its own.
      </p>
      ${last && html`<p class="hint">Last recorded by <b class="strong">${last.actor}</b> on ${formatDate(last.timestamp)}.</p>`}
    </div>
    <div class="cluster">
      ${ACTIONS.map(
        (item) => html`<button
          key=${item.action}
          class="btn"
          type="button"
          title=${item.hint}
          disabled=${busy}
          onClick=${() => void record(item.action)}
        >
          ${item.label}
        </button>`,
      )}
      <a class="btn" href=${urls.report(emailId, "csv")} title="The indicators and every finding as a spreadsheet">Export indicators</a>
    </div>
  </div>`;
}
