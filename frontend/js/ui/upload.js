import { api, friendlyError } from "../api.js";
import { formatBytes, plural } from "../format.js";
import { SAMPLES } from "../labels.js";
import { html, useEffect, useRef, useState } from "../react.js";
import { navigate } from "../router.js";
import { icon } from "./icons.js";
import { toast } from "./toast.js";

const QUEUE_FROM = 5;
const POLL_MS = 1200;
const TERMINAL = new Set(["SUCCESS", "FAILURE", "REVOKED"]);
const MAX_BYTES = 15 * 1024 * 1024;
const MAX_FILES = 500;
const MAX_PROBLEMS_SHOWN = 5;
const SNIFF_BYTES = 8;
const OLE = [0xd0, 0xcf, 0x11, 0xe0];
const SIGNATURES = [
  [[0x25, 0x50, 0x44, 0x46], "a PDF"],
  [[0x50, 0x4b, 0x03, 0x04], "a ZIP or Office file"],
  [[0x89, 0x50, 0x4e, 0x47], "a picture"],
  [[0xff, 0xd8, 0xff], "a picture"],
  [[0x47, 0x49, 0x46, 0x38], "a picture"],
];
const MIME_KINDS = [
  ["image/", "a picture"],
  ["video/", "a video"],
  ["audio/", "a sound file"],
  ["application/pdf", "a PDF"],
];
const OUTLOOK_MESSAGE =
  "is an Outlook .msg file, which MailTrace cannot read. In Outlook choose Save as, then Save as EML, or paste the message source instead.";
const HEADER_LINE = /^(received|from|to|subject|date|message-id|return-path|delivered-to):/im;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function offered(names) {
  const known = SAMPLES.filter(([name]) => names.includes(name));
  const listed = new Set(SAMPLES.map(([name]) => name));
  const extra = names
    .filter((name) => !listed.has(name))
    .map((name) => [name, name.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase())]);
  return [...known, ...extra];
}

const startsWith = (bytes, signature) => signature.every((value, index) => bytes[index] === value);

async function problemWith(file) {
  if (file.size === 0) return "is empty.";
  if (file.size > MAX_BYTES) return `is ${formatBytes(file.size)}. The limit is ${formatBytes(MAX_BYTES)}.`;
  const name = file.name.toLowerCase();
  let head;
  try {
    head = new Uint8Array(await file.slice(0, SNIFF_BYTES).arrayBuffer());
  } catch {
    return "could not be read from your device.";
  }
  if (name.endsWith(".msg")) return OUTLOOK_MESSAGE;
  if (startsWith(head, OLE)) return "is an Office document, not an email.";
  const signature = SIGNATURES.find(([bytes]) => startsWith(head, bytes));
  const mime = MIME_KINDS.find(([prefix]) => file.type.startsWith(prefix));
  const kind = signature ? signature[1] : mime ? mime[1] : "";
  return kind ? `is ${kind}, not an email. Save the email itself as a .eml file.` : "";
}

function Problems({ problems }) {
  if (problems.length === 0) return null;
  const hidden = problems.length - MAX_PROBLEMS_SHOWN;
  return html`<div class="dropzone__panel note note--bad" role="alert">
    <b>${plural(problems.length, "file")} ${problems.length === 1 ? "was" : "were"} not checked.</b>
    <ul>
      ${problems
        .slice(0, MAX_PROBLEMS_SHOWN)
        .map((problem, index) => html`<li key=${index}><b class="break">${problem.name}</b> ${problem.text}</li>`)}
      ${hidden > 0 && html`<li>and ${hidden} more.</li>`}
    </ul>
  </div>`;
}

export function Dropzone() {
  const fileInput = useRef((null));
  const pasteBox = useRef((null));
  const [panel, setPanel] = useState((null));
  const [pasted, setPasted] = useState("");
  const [pasteMissing, setPasteMissing] = useState(false);
  const [status, setStatus] = useState("");
  const [progress, setProgress] = useState((null));
  const [problems, setProblems] = useState(([]));
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [samples, setSamples] = useState(([]));
  const gone = useRef(false);
  useEffect(() => () => {
    gone.current = true;
  }, []);
  useEffect(() => {
    api
      .listSamples()
      .then((names) => {
        if (!gone.current) setSamples(offered(names));
      })
      .catch(() => {});
  }, []);

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
      toast(html`Could not check that: ${friendlyError(error)}`, "error");
    } finally {
      setBusy(false);
      setStatus("");
    }
  }

  async function runBatch(files) {
    setBusy(true);
    setStatus(`Queueing ${plural(files.length, "email")}…`);
    try {
      const { jobs } = await api.analyzeFilesAsync(files);
      if (jobs.length === 0) {
        toast("Nothing came back.", "error");
        return;
      }
      const names = new Map(jobs.map((job) => [job.job_id, job.filename]));
      const ids = jobs.map((job) => job.job_id);

      let states = jobs;
      while (!gone.current) {
        const finished = states.filter((job) => TERMINAL.has(job.state));
        setStatus(`Checked ${finished.length} of ${states.length}…`);
        setProgress({ done: finished.length, total: states.length });
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
      if (done > 0) navigate("#/cases");
    } catch (error) {
      toast(html`Could not check those: ${friendlyError(error)}`, "error");
    } finally {
      setBusy(false);
      setStatus("");
      setProgress(null);
    }
  }

  async function analyseFiles(files) {
    if (busy || !files || files.length === 0) return;
    const chosen = Array.from(files);
    if (chosen.length > MAX_FILES) {
      setProblems([
        { name: `${chosen.length} files`, text: `is more than MailTrace takes at once. Drop them in groups of ${MAX_FILES} or fewer.` },
      ]);
      return;
    }
    const verdicts = await Promise.all(chosen.map(problemWith));
    if (gone.current) return;
    setProblems(chosen.flatMap((file, index) => (verdicts[index] ? [{ name: file.name, text: verdicts[index] }] : [])));
    const accepted = chosen.filter((_, index) => !verdicts[index]);
    if (accepted.length === 0) return;
    if (accepted.length >= QUEUE_FROM) {
      void runBatch(accepted);
    } else {
      void run(() => api.analyzeFiles(accepted), plural(accepted.length, "email"));
    }
  }

  const choose = () => {
    if (!busy) fileInput.current?.click();
  };

  const openPicker = (event) => {
    if (event.target instanceof Element && event.target.closest(".dropzone__panel, button, a")) return;
    choose();
  };

  const checkPasted = () => {
    if (!pasted.trim()) {
      setPasteMissing(true);
      pasteBox.current?.focus();
      return;
    }
    void run(() => api.analyzeRaw(pasted), "the pasted email");
  };

  const pasteNote = () => {
    if (pasteMissing) {
      return html`<p id="paste-note" class="field-note field-note--bad" role="alert">Paste the email text first.</p>`;
    }
    if (pasted.trim() && !HEADER_LINE.test(pasted)) {
      return html`<p id="paste-note" class="field-note field-note--warn">
        This does not look like a whole email. It should begin with lines such as “Received:” and “From:”. You can still check it, but
        it cannot be traced back to where it came from.
      </p>`;
    }
    return null;
  };

  return html`<div
    class=${`dropzone${over ? " is-over" : ""}${busy ? " is-busy" : ""}`}
    aria-busy=${String(busy)}
    onClick=${openPicker}
    onDragOver=${(event) => {
      event.preventDefault();
      setOver(true);
    }}
    onDragLeave=${(event) => {
      if (!(event.relatedTarget instanceof Node) || !event.currentTarget.contains(event.relatedTarget)) setOver(false);
    }}
    onDrop=${(event) => {
      event.preventDefault();
      setOver(false);
      void analyseFiles(event.dataTransfer?.files ?? null);
    }}
  >
    ${busy && html`<span class="dropzone__scan"></span>`}
    <div class="dropzone__icon">${icon("mail")}</div>
    <div>
      <button class="dropzone__title" type="button" onClick=${choose}>Drop email files here, or click to choose</button>
    </div>
    <div class="hint">You can drop several at once. ${QUEUE_FROM} or more are checked in the background.</div>
    <div class="cluster cluster--center dropzone__actions">
      <button class="btn" type="button" aria-expanded=${String(panel === "paste")} onClick=${() => setPanel(panel === "paste" ? null : "paste")}>
        Or paste the email text
      </button>
      <button class="btn" type="button" aria-expanded=${String(panel === "help")} onClick=${() => setPanel(panel === "help" ? null : "help")}>
        How do I save an email?
      </button>
    </div>

    ${samples.length > 0 &&
    html`<div class="samples">
      <div class="samples__label">No email at hand? Try one of ours</div>
      <div class="cluster cluster--center">
        ${samples.map(
          ([name, label]) => html`<button
            key=${name}
            class="btn btn--pill"
            type="button"
            disabled=${busy}
            onClick=${() => void run(() => api.analyzeSample(name), `the sample “${label}”`)}
          >
            ${label}
          </button>`,
        )}
      </div>
    </div>`}

    <${Problems} problems=${problems} />

    ${panel === "help" &&
    html`<div class="dropzone__panel note note--info reveal">
      <b>You need the whole email, including its hidden headers.</b> Forwarding it to yourself will not work.
      <ul>
        <li><b>Gmail:</b> open the email, click the ⋮ menu at top right, choose <i>Download message</i>. That saves a .eml file.</li>
        <li><b>Outlook on the web and the new Outlook app:</b> right-click the email, choose <i>Save as</i>, then <i>Save as EML</i>.</li>
        <li>
          <b>Classic Outlook app:</b> it only saves .msg files, which MailTrace cannot read. Open the email, choose File, then
          Properties, copy everything in the <i>Internet headers</i> box and paste it here.
        </li>
        <li><b>Apple Mail:</b> select the email, File, Save As, format <i>Raw Message Source</i>.</li>
      </ul>
    </div>`}

    ${panel === "paste" &&
    html`<div class="dropzone__panel reveal">
      <label class="sr-only" for="paste-box">The email source</label>
      <textarea
        id="paste-box"
        ref=${pasteBox}
        class=${`input input--area${pasteMissing ? " is-invalid" : ""}`}
        placeholder=${'Paste the whole message source here, starting from the lines that look like "Received:" and "From:"…'}
        aria-invalid=${String(pasteMissing)}
        aria-describedby="paste-note"
        value=${pasted}
        onChange=${(event) => {
          setPasted(event.target.value);
          setPasteMissing(false);
        }}
      ></textarea>
      ${pasteNote()}
      <div class="cluster cluster--end dropzone__actions">
        <button class=${`btn btn--primary${busy ? " is-busy" : ""}`} type="button" disabled=${busy} onClick=${checkPasted}>
          Check this email
        </button>
      </div>
    </div>`}

    ${status && html`<div class="upload-status" role="status">${status}</div>`}
    ${progress &&
    html`<div
      class="progress"
      role="progressbar"
      aria-label="Emails checked so far"
      aria-valuemin="0"
      aria-valuemax=${progress.total}
      aria-valuenow=${progress.done}
    >
      <div class="progress__fill" style=${{ "--value": String((progress.done / progress.total) * 100) }}></div>
    </div>`}

    <input
      type="file"
      multiple
      hidden
      aria-hidden="true"
      tabIndex=${-1}
      ref=${fileInput}
      onChange=${(event) => {
        void analyseFiles(event.target.files);
        event.target.value = "";
      }}
    />
  </div>`;
}
