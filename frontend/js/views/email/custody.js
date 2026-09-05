// @ts-check
/** "Evidence log": the hash-linked chain of custody, and the ledger check. */
import { api, errorMessage } from "../../api.js";
import { formatDate, truncate } from "../../format.js";
import { useAsync } from "../../hooks.js";
import { CUSTODY_ACTION } from "../../labels.js";
import { html } from "../../react.js";
import { chip, errorState, section, skeleton } from "../../ui/primitives.js";
import { toast } from "../../ui/toast.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').CustodyEvent} CustodyEvent */

const HASH_PREVIEW_CHARS = 16;
const FINGERPRINT_PREVIEW_CHARS = 32;

/**
 * @param {{ event: CustodyEvent }} props
 */
function EventRow({ event }) {
  return html`<tr>
    <td class="mono">${event.seq}</td>
    <td class="small nowrap">${formatDate(event.timestamp)}</td>
    <td>${event.actor}</td>
    <td>${chip(CUSTODY_ACTION[event.action] ?? event.action, "teal")}</td>
    <td class="mono small">${event.hash.slice(0, HASH_PREVIEW_CHARS)}…</td>
  </tr>`;
}

/**
 * @param {{ result: AnalysisResult }} props
 */
export function CustodyTab({ result }) {
  const { data, error, loading, reload } = useAsync(() => api.getCustody(result.id), [result.id]);

  async function verify() {
    try {
      const verdict = await api.verifyCustody();
      toast(
        verdict.valid ? "Checked: the evidence log is intact, nothing has been altered." : "Warning: the evidence log has been altered.",
        verdict.valid ? "success" : "error",
      );
      reload();
    } catch (cause) {
      toast(html`Could not check: ${errorMessage(cause)}`, "error");
    }
  }

  if (error) return errorState(error, reload);
  if (loading || !data) return skeleton(2);

  return section(
    "Evidence log",
    html`<div class="cluster cluster--loose custody-status">
        ${data.valid ? chip("✓ Untampered", "ok") : chip("✕ ALTERED", "bad")}
        <span class="hint">
          Original email fingerprint (SHA-256):
          <span class="mono">${truncate(result.email.raw_sha256, FINGERPRINT_PREVIEW_CHARS)}</span>
        </span>
      </div>
      <div class="table-wrap"><table class="table">
        <thead><tr><th>#</th><th>When</th><th>Who</th><th>What happened</th><th>Fingerprint</th></tr></thead>
        <tbody>
          ${data.events.length > 0
            ? data.events.map((event) => html`<${EventRow} key=${event.seq} event=${event} />`)
            : html`<tr><td colSpan=${5} class="muted">No entries.</td></tr>`}
        </tbody>
      </table></div>`,
    {
      aside: html`<button class="btn" type="button" onClick=${() => void verify()}>Check it was not tampered with</button>`,
      note: "Every action is stamped and linked to the one before it, like a chain. If anyone edits the history, the chain breaks. This is what makes the evidence usable in a legal case.",
    },
  );
}
