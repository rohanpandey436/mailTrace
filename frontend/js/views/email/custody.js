// @ts-check
/** "Evidence log": the hash-linked chain of custody, and the ledger check. */
import { api, errorMessage } from "../../api.js";
import { html, mount, must } from "../../dom.js";
import { formatDate, truncate } from "../../format.js";
import { CUSTODY_ACTION } from "../../labels.js";
import { chip, emptyState, section } from "../../ui/primitives.js";
import { toast } from "../../ui/toast.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').CustodyChain} CustodyChain */
/** @typedef {import('../../types.js').CustodyEvent} CustodyEvent */

const HASH_PREVIEW_CHARS = 16;
const FINGERPRINT_PREVIEW_CHARS = 32;

/**
 * @param {CustodyEvent} event
 */
function eventRow(event) {
  return html`<tr>
    <td class="mono">${event.seq}</td>
    <td class="small nowrap">${formatDate(event.timestamp)}</td>
    <td>${event.actor}</td>
    <td>${chip(CUSTODY_ACTION[event.action] ?? event.action, "teal")}</td>
    <td class="mono small">${event.hash.slice(0, HASH_PREVIEW_CHARS)}…</td>
  </tr>`;
}

/**
 * @param {AnalysisResult} result
 * @param {CustodyChain} chain
 */
function custodyTab(result, chain) {
  return section(
    "Evidence log",
    html`<div class="cluster cluster--loose custody-status">
        ${chain.valid ? chip("✓ Untampered", "ok") : chip("✕ ALTERED", "bad")}
        <span class="hint">Original email fingerprint (SHA-256): <span class="mono">${truncate(result.email.raw_sha256, FINGERPRINT_PREVIEW_CHARS)}</span></span>
      </div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>#</th><th>When</th><th>Who</th><th>What happened</th><th>Fingerprint</th></tr></thead>
        <tbody>${chain.events.length > 0 ? chain.events.map(eventRow) : html`<tr><td colspan="5" class="muted">No entries.</td></tr>`}</tbody>
      </table></div>`,
    {
      aside: html`<button class="btn" type="button" id="verify-btn">Check it was not tampered with</button>`,
      note: "Every action is stamped and linked to the one before it, like a chain. If anyone edits the history, the chain breaks. This is what makes the evidence usable in a legal case.",
    },
  );
}

/**
 * Returns a cleanup that cancels the render if the tab changes before the
 * log arrives.
 * @param {HTMLElement} panel
 * @param {AnalysisResult} result
 * @returns {() => void}
 */
export function mountCustodyTab(panel, result) {
  let cancelled = false;

  async function load() {
    try {
      const chain = await api.getCustody(result.id);
      if (cancelled) return;
      mount(panel, custodyTab(result, chain));
      must("#verify-btn", panel).addEventListener("click", () => void verify());
    } catch (error) {
      if (!cancelled) mount(panel, emptyState("Could not load the evidence log", errorMessage(error)));
    }
  }

  async function verify() {
    try {
      const verdict = await api.verifyCustody();
      toast(
        verdict.valid ? "Checked: the evidence log is intact, nothing has been altered." : "Warning: the evidence log has been altered.",
        verdict.valid ? "success" : "error",
      );
      await load();
    } catch (error) {
      toast(html`Could not check: ${errorMessage(error)}`, "error");
    }
  }

  void load();
  return () => {
    cancelled = true;
  };
}
