import { api, friendlyError } from "../api.js";
import { formatDate } from "../format.js";
import { useAsync } from "../hooks.js";
import { subscribeToAlerts } from "../live-feed.js";
import { Fragment, html, useEffect, useState } from "../react.js";
import { unreadAlerts } from "../state.js";
import { categoryChip, chip, emptyState, errorState, loadingState, pageHead, riskBar } from "../ui/primitives.js";
import { toast } from "../ui/toast.js";

const LIST_LIMIT = 100;

export async function refreshUnreadCount() {
  try {
    unreadAlerts.set((await api.listAlerts({ limit: LIST_LIMIT, unacknowledgedOnly: true })).length);
  } catch {
  }
}

function AlertRow({ alert, onAcknowledged }) {
  const [busy, setBusy] = useState(false);
  async function acknowledge() {
    setBusy(true);
    try {
      await api.acknowledgeAlert(alert.id);
      onAcknowledged(alert.id);
      void refreshUnreadCount();
    } catch (error) {
      setBusy(false);
      toast(html`Could not update: ${friendlyError(error)}`, "error");
    }
  }
  return html`<div class="card card--tight alert-row">
    <div>${riskBar(alert.risk_score, alert.severity)}</div>
    <div class="spread">
      <div class="alert-row__title">
        ${categoryChip(alert.category)}
        <a class="truncate" href=${`#/email/${encodeURIComponent(alert.email_id)}`}>${alert.subject || "(no subject)"}</a>
      </div>
      <div class="hint truncate">${alert.sender} · ${formatDate(alert.created_at)}</div>
    </div>
    ${alert.acknowledged
      ? chip("seen")
      : html`<button class=${`btn${busy ? " is-busy" : ""}`} type="button" disabled=${busy} onClick=${() => void acknowledge()}>Mark as seen</button>`}
  </div>`;
}

export function AlertsView() {
  const { data, error, loading, slow, reload } = useAsync(() => api.listAlerts({ limit: LIST_LIMIT }), []);
  const [live, setLive] = useState(([]));
  const [seen, setSeen] = useState((new Set()));

  useEffect(() => {
    unreadAlerts.set(0);
    return subscribeToAlerts((alert) => setLive((current) => [alert, ...current]));
  }, []);

  if (error) return errorState(error, reload);

  const alerts = loading || !data ? [] : [...live, ...data];
  const body = () => {
    if (loading || !data) return loadingState(3, slow);
    if (alerts.length === 0) return emptyState("No alerts", "Anything scoring above the alert level will show up here straight away.");
    return alerts.map(
      (alert) => html`<${AlertRow}
        key=${alert.id}
        alert=${seen.has(alert.id) ? { ...alert, acknowledged: true } : alert}
        onAcknowledged=${(id) => setSeen((current) => new Set(current).add(id))}
      />`,
    );
  };

  return html`<${Fragment}>
    ${pageHead("Alerts", "Raised the moment a dangerous email is checked, so nobody has to be watching the screen.")}
    <div class="stack">${body()}</div>
  </>`;
}
