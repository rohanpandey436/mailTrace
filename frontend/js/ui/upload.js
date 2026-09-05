// @ts-check
/** The drop zone: choose or drop `.eml` files, or paste the raw message source. */
import { api, errorMessage } from "../api.js";
import { plural } from "../format.js";
import { html, useRef, useState } from "../react.js";
import { navigate } from "../router.js";
import { toast } from "./toast.js";

/** @typedef {import('../types.js').AnalyzeResponse} AnalyzeResponse */
/** @typedef {'help' | 'paste' | null} OpenPanel */

export function Dropzone() {
  const fileInput = useRef(/** @type {HTMLInputElement | null} */ (null));
  const [panel, setPanel] = useState(/** @type {OpenPanel} */ (null));
  const [pasted, setPasted] = useState("");
  const [status, setStatus] = useState("");
  const [over, setOver] = useState(false);

  /**
   * @param {() => Promise<AnalyzeResponse>} call
   * @param {string} label what is being checked, for the status line
   */
  async function run(call, label) {
    setStatus(`Checking ${label}… this takes a few seconds when internet lookups are on.`);
    try {
      const { results } = await call();
      if (results.length === 0) {
        toast("Nothing came back.", "error");
        return;
      }
      if (results.some((result) => result.headers.hops.length > 0)) {
        toast(`Done. Checked ${plural(results.length, "email")}.`);
      } else {
        toast(
          html`Checked, but this email had <b>no delivery headers</b>, so it could not be traced. See the note on the next screen.`,
          "alert",
        );
      }
      navigate(`#/email/${encodeURIComponent(results[0].id)}`);
    } catch (error) {
      toast(html`Could not check that: ${errorMessage(error)}`, "error");
    } finally {
      setStatus("");
    }
  }

  /** @param {FileList | null} files */
  const analyseFiles = (files) => {
    if (files && files.length > 0) void run(() => api.analyzeFiles(files), plural(files.length, "email"));
  };

  /** Clicks inside a panel, or on a button, are not a request for the file picker. */
  const openPicker = (/** @type {{ target: EventTarget | null }} */ event) => {
    if (event.target instanceof Element && event.target.closest(".dropzone__panel, button")) return;
    fileInput.current?.click();
  };

  return html`<div
    class=${`dropzone${over ? " is-over" : ""}`}
    role="button"
    tabIndex=${0}
    aria-label="Choose email files to check"
    onClick=${openPicker}
    onDragOver=${(/** @type {DragEvent} */ event) => {
      event.preventDefault();
      setOver(true);
    }}
    onDragLeave=${() => setOver(false)}
    onDrop=${(/** @type {DragEvent} */ event) => {
      event.preventDefault();
      setOver(false);
      analyseFiles(event.dataTransfer?.files ?? null);
    }}
  >
    <div class="dropzone__icon">📩</div>
    <div class="dropzone__title">Drop email files here, or click to choose</div>
    <div class="hint">You can drop several at once.</div>
    <div class="cluster cluster--center dropzone__actions">
      <button class="btn" type="button" onClick=${() => setPanel(panel === "paste" ? null : "paste")}>Or paste the email text</button>
      <button class="btn" type="button" onClick=${() => setPanel(panel === "help" ? null : "help")}>How do I save an email?</button>
    </div>

    ${panel === "help" &&
    html`<div class="dropzone__panel note note--info">
      <b>You need the whole email, including its hidden headers.</b> Forwarding it to yourself will not work.
      <ul>
        <li><b>Gmail:</b> open the email, click the ⋮ menu at top right, choose <i>Download message</i>. That saves a .eml file.</li>
        <li><b>Outlook app:</b> open the email, File, Save As, and pick <i>Outlook Message Format</i>.</li>
        <li><b>Outlook web:</b> ⋯ menu, <i>View</i>, <i>View message source</i>, then copy everything into the paste box.</li>
        <li><b>Apple Mail:</b> select the email, File, Save As, format <i>Raw Message Source</i>.</li>
      </ul>
    </div>`}

    ${panel === "paste" &&
    html`<div class="dropzone__panel">
      <textarea
        class="input input--area"
        placeholder=${'Paste the whole message source here, starting from the lines that look like "Received:" and "From:"…'}
        value=${pasted}
        onChange=${(/** @type {{ target: HTMLTextAreaElement }} */ event) => setPasted(event.target.value)}
      ></textarea>
      <div class="cluster cluster--end dropzone__actions">
        <button
          class="btn btn--primary"
          type="button"
          onClick=${() => {
            if (!pasted.trim()) {
              toast("Paste the email text first.", "error");
              return;
            }
            void run(() => api.analyzeRaw(pasted), "the pasted email");
          }}
        >
          Check this email
        </button>
      </div>
    </div>`}

    ${status && html`<div class="upload-status">${status}</div>`}

    <input
      type="file"
      multiple
      hidden
      ref=${fileInput}
      onChange=${(/** @type {{ target: HTMLInputElement }} */ event) => {
        analyseFiles(event.target.files);
        event.target.value = "";
      }}
    />
  </div>`;
}
