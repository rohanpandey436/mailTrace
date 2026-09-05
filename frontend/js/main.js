// @ts-check
/** Entry point: register the views, wire the shell, start the router and the feed. */
import { api } from "./api.js";
import { $$, activatable, html, mount, must } from "./dom.js";
import { truncate } from "./format.js";
import { categoryOf } from "./labels.js";
import { startLiveFeed } from "./live-feed.js";
import { currentRoute, defineView, navigate, refresh, startRouter } from "./router.js";
import { preferences, session, setPreference } from "./state.js";
import { bindCaseRows } from "./ui/cases-table.js";
import { toast } from "./ui/toast.js";
import { alertsView, bindAlertActions, prependAlert, refreshUnreadCount, setUnreadCount } from "./views/alerts.js";
import { campaignView, campaignsView } from "./views/campaigns.js";
import { casesView } from "./views/cases.js";
import { dashboardView } from "./views/dashboard.js";
import { emailView } from "./views/email/index.js";

/** @typedef {import('./types.js').Alert} Alert */

const MAX_TOAST_SUBJECT = 60;

defineView("dashboard", dashboardView);
defineView("cases", casesView);
defineView("email", emailView);
defineView("campaigns", (container, id) => (id ? campaignView(container, id) : campaignsView(container, id)));
defineView("alerts", alertsView);

/**
 * @param {import('./router.js').Route} route
 */
function highlightNav(route) {
  $$(".rail__link").forEach((link) => link.classList.toggle("is-active", link.dataset.route === route.name));
}

function bindSearch() {
  const input = /** @type {HTMLInputElement} */ (must("#search"));
  must("#search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    session.listFilters.q = input.value.trim();
    session.listFilters.page = 0;
    navigate("#/cases");
  });
}

/** @type {(() => void) | null} */
let stopLiveFeed = null;

function connectLiveFeed() {
  stopLiveFeed?.();
  stopLiveFeed = startLiveFeed(onAlert);
}

function bindMaskSwitch() {
  const control = must("#mask-switch");
  const render = () => {
    control.classList.toggle("is-on", preferences.mask);
    control.setAttribute("aria-checked", String(preferences.mask));
  };
  render();
  activatable(control, () => {
    setPreference("mask", !preferences.mask);
    render();
    toast(preferences.mask ? "Personal details are now hidden everywhere." : "Personal details are shown again.");
    connectLiveFeed(); // the feed is masked at connection time
    void refresh();
  });
}

async function loadHealth() {
  const badge = must("#net-badge");
  try {
    const health = await api.health();
    session.health = health;
    mount(
      badge,
      health.network
        ? html`<span class="status-dot tone-ok"></span>Internet lookups on`
        : html`<span class="status-dot tone-warn"></span>Offline mode`,
    );
    badge.title = health.network
      ? "Location, domain age and blocklist checks are working"
      : "No location or domain-age data will be collected";
  } catch {
    badge.textContent = "Server not reachable";
  }
}

/**
 * @param {Alert} alert
 */
function onAlert(alert) {
  setUnreadCount(session.unreadAlerts + 1);
  toast(
    html`<b>${categoryOf(alert.category).label}</b> · risk ${alert.risk_score}<br>
      <a class="link" href="#/email/${encodeURIComponent(alert.email_id)}">${truncate(alert.subject, MAX_TOAST_SUBJECT) || "Open it"}</a>`,
    "alert",
  );
  if (currentRoute().name === "alerts") prependAlert(alert);
}

bindCaseRows(document);
bindAlertActions(document);
bindSearch();
bindMaskSwitch();
void loadHealth().then(() => {
  startRouter(must("#view"), highlightNav);
  void refreshUnreadCount();
  connectLiveFeed();
});
