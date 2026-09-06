// @ts-check
/** The drop zone: choose or drop `.eml` files, or paste the raw message source. */
import { api, errorMessage } from "../api.js";
import { plural } from "../format.js";
import { html, useEffect, useRef, useState } from "../react.js";
import { navigate } from "../router.js";
import { toast } from "./toast.js";

/** @typedef {import('../types.js').AnalyzeResponse} AnalyzeResponse */
/** @typedef {import('../types.js').JobStatus} JobStatus */
/** @typedef {'help' | 'paste' | null} OpenPanel */

/** Batches of this size or more go through the queue; smaller ones use the direct endpoint and land on the case. */
const QUEUE_FROM = 5;
const POLL_MS = 1200;
/** A job that will never change again. */
const TERMINAL = new Set(["SUCCESS", "FAILURE", "REVOKED"]);

/** @param {number} ms */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export function Dropzone() {
  const fileInput = useRef(/** @type {HTMLInputElement | null} */ (null));
  const [panel, setPanel] = useState(/** @type {OpenPanel} */ (null));
  const [pasted, setPasted] = useState("");
  const [status, setStatus] = useState("");
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const gone = useRef(false);
  useEffect(() => () => {
    gone.current = true;
  }, []);

  /**
   * @param {() => Promise<AnalyzeResponse>} call
   * @param {string} label what is being checked, for the status line
   */
  async function run(call, label) {
    setBusy(true);
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
      setBusy(false);
      setStatus("");
    }
  }

  /**
   * Queue a batch and poll it to completion. With a broker the upload returns
   * immediately and a worker does the work; without one every job is already
   * finished on the first poll.
   * @param {File[]} files
   */
  async function runBatch(files) {
    setBusy(true);
    setStatus(`Queueing ${plural(files.length, "email")}…`);
    try {
      const { jobs } = await api.analyzeFilesAsync(files);
      if (jobs.length === 0) {
        toast("Nothing came back.", "error");
        return;
      }
      /** @type {Map<string, string>} filenames, which only the submission knows */
      const names = new Map(jobs.map((job) => [job.job_id, job.filename]));
      const ids = jobs.map((job) => job.job_id);

      /** @type {JobStatus[]} */
      let states = jobs;
      while (!gone.current) {
        const finished = states.filter((job) => TERMINAL.has(job.state));
        setStatus(`Checked ${finished.length} of ${states.length}…`);
        if (finished.length === states.length) break;
        await sleep(POLL_MS);
        if (gone.current) return;
        states = await api.jobs(ids);
      }
      if (gone.current) return;

      const failed = states.filter((job) => job.state !== "SUCCESS");
      const done = states.length - failed.length;
      if (done > 0) toast(`Done. Checked ${plural(done, "email")}.`);
      if (failed.length > 0) {
        const first = names.get(failed[0].job_id) || failed[0].job_id;
        toast(html`${plural(failed.length, "email")} could not be checked, starting with <b>${first}</b>.`, "error");
      }
      // The list, not one case: a batch has no single result to land on.
      if (done > 0) navigate("#/cases");
    } catch (error) {
      toast(html`Could not check those: ${errorMessage(error)}`, "error");
    } finally {
      setBusy(false);
      setStatus("");
    }
  }

  /** @param {FileList | null} files */
  const analyseFiles = (files) => {
    if (busy || !files || files.length === 0) return;
    const chosen = Array.from(files);
    if (chosen.length >= QUEUE_FROM) {
      void runBatch(chosen);
    } else {
      void run(() => api.analyzeFiles(chosen), plural(chosen.length, "email"));
    }
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
    aria-busy=${String(busy)}
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
    <div class="hint">You can drop several at once. ${QUEUE_FROM} or more are checked in the background.</div>
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
