import { api, friendlyError } from "../api.js";
import { formatDate, plural } from "../format.js";
import { ORIGIN } from "../labels.js";
import { html, useEffect, useState } from "../react.js";
import { chip } from "./primitives.js";
import { toast } from "./toast.js";

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export function timeLeft(seconds) {
  const total = Math.max(0, Math.floor(seconds ?? 0));
  if (total < MINUTE) return "less than a minute";
  if (total < HOUR) return plural(Math.floor(total / MINUTE), "minute");
  if (total < 2 * DAY) {
    const hours = Math.floor(total / HOUR);
    const minutes = Math.floor((total % HOUR) / MINUTE);
    return minutes > 0 ? `${hours} h ${minutes} min` : plural(hours, "hour");
  }
  return plural(Math.floor(total / DAY), "day");
}

function visibility(retention) {
  return retention.listed
    ? "It appears in the lists on this dashboard."
    : "It is not listed anywhere on this dashboard: only someone who has this link can open it.";
}

export function RetentionBar({ emailId }) {
  const [retention, setRetention] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .getRetention(emailId)
      .then((current) => {
        if (!cancelled) setRetention(current);
      })
      .catch(() => {
      });
    return () => {
      cancelled = true;
    };
  }, [emailId]);

  if (!retention) return null;
  if (retention.state === "permanent" && retention.listed && retention.origin === "dashboard") return null;

  const origin = ORIGIN[retention.origin] ?? ORIGIN.dashboard;

  async function freeze() {
    setBusy(true);
    try {
      setRetention(await api.freezeEvidence(emailId));
      toast("Frozen. This case will not be deleted and the evidence log records who preserved it.", "success");
    } catch (error) {
      toast(html`Could not freeze this case: ${friendlyError(error)}`, "error");
    } finally {
      setBusy(false);
    }
  }

  if (retention.state === "expiring") {
    return html`<div class="section">
      <div class="card card--tight cluster cluster--top cluster--loose">
        <div class="spread">
          <div class="decision__title">
            ${origin.title} ${chip(`Deletes itself in ${timeLeft(retention.seconds_left)}`, "warn")}
          </div>
          <p class="hint">
            ${origin.detail} ${visibility(retention)} The analysis, the original email and its indicators will be
            <b class="strong"> deleted on ${formatDate(retention.expires_at)}</b>. Only the entry in the evidence log stays, so the
            log remains complete.
          </p>
          <p class="hint">Freeze the case if it has to be kept for a complaint or an investigation.</p>
        </div>
        <div class="cluster">
          <button
            class=${`btn btn--primary${busy ? " is-busy" : ""}`}
            type="button"
            title="Cancels the automatic deletion and records who preserved the case"
            disabled=${busy}
            onClick=${() => void freeze()}
          >
            Freeze and preserve as evidence
          </button>
        </div>
      </div>
    </div>`;
  }

  if (retention.state === "frozen") {
    return html`<div class="section">
      <div class="card card--tight cluster cluster--top cluster--loose">
        <div class="spread">
          <div class="decision__title">${origin.title} ${chip("Preserved as evidence", "ok")}</div>
          <p class="hint">
            Frozen by <b class="strong">${retention.frozen_by || "an analyst"}</b> on ${formatDate(retention.frozen_at)}. Automatic
            deletion is cancelled and the case is kept until an administrator removes it. ${visibility(retention)}
          </p>
        </div>
      </div>
    </div>`;
  }

  return html`<div class="section">
    <div class="card card--tight cluster cluster--top cluster--loose">
      <div class="spread">
        <div class="decision__title">${origin.title} ${chip("Kept", "neutral")}</div>
        <p class="hint">${origin.detail} ${visibility(retention)}</p>
      </div>
    </div>
  </div>`;
}
