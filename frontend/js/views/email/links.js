// @ts-check
/**
 * "Links & files": every link with where it really goes, and every
 * attachment with what it really is.
 */
import { html } from "../../dom.js";
import { formatBytes, truncate } from "../../format.js";
import { chip, section, severityChip } from "../../ui/primitives.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').AttachmentMeta} AttachmentMeta */
/** @typedef {import('../../types.js').UrlInfo} UrlInfo */

const MAX_URL_CHARS = 150;
const MAX_ANCHOR_CHARS = 70;
/** Shannon entropy is measured in bits per byte; 8 is completely random. */
const ENTROPY_MAX = 8;

/**
 * @param {UrlInfo} url
 */
function urlRow(url) {
  return html`<tr>
    <td>${severityChip(url.risk)}</td>
    <td class="col-url">
      <div class="mono break">${truncate(url.url, MAX_URL_CHARS)}</div>
      ${url.anchor_text &&
      html`<div class="url__anchor${url.anchor_mismatch ? " is-mismatch" : ""}">shown as: ${truncate(url.anchor_text, MAX_ANCHOR_CHARS)}${url.anchor_mismatch && " — but it does not go there!"}</div>`}
    </td>
    <td class="hint">${url.reasons.join("; ") || "nothing unusual"}</td>
  </tr>`;
}

/**
 * @param {AttachmentMeta} file
 */
function fileRow(file) {
  return html`<tr>
    <td>${severityChip(file.risk)}</td>
    <td>
      <div class="strong break">${file.filename}</div>
      <div class="file__flags">
        ${file.double_extension && chip("disguised file type", "bad")}
        ${file.has_macros && chip("contains macros", "bad")}
        ${file.mime_mismatch && chip("not what it claims to be", "bad")}
      </div>
      <div class="mono file__hash">${file.sha256}</div>
    </td>
    <td class="small">
      ${formatBytes(file.size)}
      <div class="muted" title="Shannon entropy in bits per byte. 8.0 is completely random, which means compressed, encrypted or packed.">
        randomness ${file.shannon_entropy.toFixed(2)}/${ENTROPY_MAX}${file.high_entropy && html` <span class="text-bad strong">high</span>`}
      </div>
    </td>
    <td class="hint">${file.reasons.join("; ") || "nothing unusual"}</td>
  </tr>`;
}

/**
 * @param {AnalysisResult} result
 */
export function linksTab(result) {
  const urls = result.urls.urls;
  const files = result.attachments.attachments;
  const urlTable =
    urls.length > 0
      ? html`<div class="table-wrap"><table class="table">
          <thead><tr><th>Danger</th><th>Where it really goes</th><th>Why it is a problem</th></tr></thead>
          <tbody>${urls.map(urlRow)}</tbody>
        </table></div>`
      : html`<div class="hint">This email contains no links.</div>`;
  const fileTable =
    files.length > 0
      ? html`<div class="table-wrap"><table class="table">
          <thead><tr><th>Danger</th><th>File</th><th>Size</th><th>Why it is a problem</th></tr></thead>
          <tbody>${files.map(fileRow)}</tbody>
        </table></div>`
      : html`<div class="hint">This email has no attachments.</div>`;
  return html`${section("Links in this email", urlTable, { note: "We follow what the link actually does, not what it says on screen." })}
    ${section("Attached files", fileTable, { note: "We look inside the file, not just at its name." })}`;
}
