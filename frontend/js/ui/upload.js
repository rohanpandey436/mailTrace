// @ts-check
/**
 * The drop zone on the home page: choose or drop `.eml` files, or paste the
 * raw message source.  Either way the analysis runs and the browser lands on
 * the first result.
 */
import { api, errorMessage } from "../api.js";
import { html, must } from "../dom.js";
import { plural } from "../format.js";
import { toast } from "./toast.js";

/** @typedef {import('../types.js').AnalyzeResponse} AnalyzeResponse */

export function dropzone() {
  return html`<div id="dropzone" class="dropzone" role="button" tabindex="0" aria-label="Choose email files to check">
    <div class="dropzone__icon">📩</div>
    <div class="dropzone__title">Drop email files here, or click to choose</div>
    <div class="hint">You can drop several at once.</div>
    <div class="cluster cluster--center dropzone__actions">
      <button class="btn" id="paste-toggle" type="button">Or paste the email text</button>
      <button class="btn" id="help-toggle" type="button">How do I save an email?</button>
    </div>
    <div id="help-box" class="dropzone__panel note note--info" hidden>
      <b>You need the whole email, including its hidden headers.</b> Forwarding it to yourself will not work.
      <ul>
        <li><b>Gmail:</b> open the email, click the ⋮ menu at top right, choose <i>Download message</i>. That saves a .eml file.</li>
        <li><b>Outlook app:</b> open the email, File, Save As, and pick <i>Outlook Message Format</i>.</li>
        <li><b>Outlook web:</b> ⋯ menu, <i>View</i>, <i>View message source</i>, then copy everything into the paste box.</li>
        <li><b>Apple Mail:</b> select the email, File, Save As, format <i>Raw Message Source</i>.</li>
      </ul>
    </div>
    <div id="paste-box" class="dropzone__panel" hidden>
      <textarea id="paste-text" class="input input--area" placeholder="Paste the whole message source here, starting from the lines that look like &quot;Received:&quot; and &quot;From:&quot;…"></textarea>
      <div class="cluster cluster--end dropzone__actions"><button class="btn btn--primary" id="paste-submit" type="button">Check this email</button></div>
    </div>
    <div id="upload-status" class="upload-status" hidden></div>
  </div>`;
}

/**
 * Wire the drop zone rendered by `dropzone()`.
 * @param {HTMLElement} zone
 * @param {HTMLInputElement} fileInput the page's hidden file input
 */
export function bindUpload(zone, fileInput) {
  const pasteBox = must("#paste-box", zone);
  const helpBox = must("#help-box", zone);
  const status = must("#upload-status", zone);
  const pasteText = /** @type {HTMLTextAreaElement} */ (must("#paste-text", zone));

  zone.addEventListener("click", (event) => {
    // Clicks inside the paste and help panels, or on their buttons, are not a
    // request to open the file picker.
    if (event.target instanceof Element && event.target.closest(".dropzone__panel, button")) return;
    fileInput.click();
  });
  zone.addEventListener("dragover", (event) => {
    event.preventDefault();
    zone.classList.add("is-over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("is-over"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("is-over");
    const files = event.dataTransfer?.files;
    if (files && files.length > 0) void run(() => api.analyzeFiles(files), plural(files.length, "email"));
  });
  // Assigned, not added: the input outlives the page and must not collect handlers.
  fileInput.onchange = () => {
    const files = fileInput.files;
    if (files && files.length > 0) void run(() => api.analyzeFiles(files), plural(files.length, "email"));
    fileInput.value = "";
  };

  must("#paste-toggle", zone).addEventListener("click", () => {
    pasteBox.hidden = !pasteBox.hidden;
    helpBox.hidden = true;
  });
  must("#help-toggle", zone).addEventListener("click", () => {
    helpBox.hidden = !helpBox.hidden;
    pasteBox.hidden = true;
  });
  must("#paste-submit", zone).addEventListener("click", () => {
    const raw = pasteText.value;
    if (!raw.trim()) {
      toast("Paste the email text first.", "error");
      return;
    }
    void run(() => api.analyzeRaw(raw), "the pasted email");
  });

  /**
   * @param {() => Promise<AnalyzeResponse>} call
   * @param {string} label what is being checked, for the status line
   */
  async function run(call, label) {
    status.hidden = false;
    status.textContent = `Checking ${label}… this takes a few seconds when internet lookups are on.`;
    try {
      const { results } = await call();
      if (results.length === 0) {
        toast("Nothing came back.", "error");
        return;
      }
      const traceable = results.some((result) => result.headers.hops.length > 0);
      if (traceable) {
        toast(`Done. Checked ${plural(results.length, "email")}.`);
      } else {
        toast(
          html`Checked, but this email had <b>no delivery headers</b>, so it could not be traced. See the note on the next screen.`,
          "alert",
        );
      }
      location.hash = `#/email/${encodeURIComponent(results[0].id)}`;
    } catch (error) {
      toast(html`Could not check that: ${errorMessage(error)}`, "error");
    } finally {
      status.hidden = true;
    }
  }
}
