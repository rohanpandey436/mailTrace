// @ts-check
/** Alerts: the list, the unread badges, and the "mark as seen" action. */
import { api, errorMessage } from "../api.js";
import { $, html, mount, must, on } from "../dom.js";
import { formatDate } from "../format.js";
import { session } from "../state.js";
import { categoryChip, chip, emptyState, pageHead, riskBar, skeleton } from "../ui/primitives.js";
import { toast } from "../ui/toast.js";

/** @typedef {import('../types.js').Alert} Alert */

const LIST_LIMIT = 100;

/**
 * @param {Alert} alert
 */
function alertRow(alert) {
  return html`<div class="card card--tight alert-row">
    <div>${riskBar(alert.risk_score, alert.severity)}</div>
    <div class="spread">
      <div class="alert-row__title">
        ${categoryChip(alert.category)}
        <a class="truncate" href="#/email/${encodeURIComponent(alert.email_id)}">${alert.subject || "(no subject)"}</a>
      </div>
      <div class="hint truncate">${alert.sender} · ${formatDate(alert.created_at)}</div>
    </div>
    ${alert.acknowledged ? chip("seen") : html`<button class="btn" type="button" data-ack="${alert.id}">Mark as seen</button>`}
  </div>`;
}

/** @type {import('../router.js').View} */
export async function alertsView(container) {
  mount(
    container,
    html`${pageHead("Alerts", "Raised the moment a dangerous email is checked, so nobody has to be watching the screen.")}
      <div id="alerts" class="stack">${skeleton(3)}</div>`,
  );
  const alerts = await api.listAlerts({ limit: LIST_LIMIT });
  mount(
    must("#alerts", container),
    alerts.length > 0
      ? html`${alerts.map(alertRow)}`
      : emptyState("No alerts", "Anything scoring above the alert level will show up here straight away."),
  );
  setUnreadCount(0);
}

/**
 * No-op unless the alert list is the view on screen.
 * @param {Alert} alert
 */
export function prependAlert(alert) {
  const list = $("#alerts");
  if (!list) return;
  list.querySelector(".empty")?.remove();
  list.insertAdjacentHTML("afterbegin", String(alertRow(alert)));
}

/**
 * @param {number} count
 */
export function setUnreadCount(count) {
  session.unreadAlerts = count;
  for (const badge of [$("#bell-count"), $("#nav-alert-count")]) {
    if (!badge) continue;
    badge.textContent = String(count);
    badge.hidden = count <= 0;
  }
}

export async function refreshUnreadCount() {
  try {
    setUnreadCount((await api.listAlerts({ limit: LIST_LIMIT, unacknowledgedOnly: true })).length);
  } catch {
    // The badge keeps its last value; the next alert or page load corrects it.
  }
}

/**
 * "Mark as seen" for any alert row, registered once on the document.
 * @param {Document} root
 */
export function bindAlertActions(root) {
  on(root, "click", "[data-ack]", async (_event, target) => {
    const button = /** @type {HTMLButtonElement} */ (target);
    const id = button.dataset.ack;
    if (!id) return;
    button.disabled = true;
    try {
      await api.acknowledgeAlert(id);
      button.outerHTML = String(chip("seen"));
      void refreshUnreadCount();
    } catch (error) {
      button.disabled = false;
      toast(html`Could not update: ${errorMessage(error)}`, "error");
    }
  });
}
