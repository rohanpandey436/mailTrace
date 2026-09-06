// @ts-check
/** Entry point: the app shell, the route switch, and the live alert feed. */
import { api } from "./api.js";
import { truncate } from "./format.js";
import { useStore } from "./hooks.js";
import { categoryOf } from "./labels.js";
import { resyncMask, subscribeToAlerts } from "./live-feed.js";
import { Fragment, html, useEffect, useState } from "./react.js";
import { navigate, useRoute } from "./router.js";
import { preferences, session, setPreference, unreadAlerts } from "./state.js";
import { Toasts, toast } from "./ui/toast.js";
import { AlertsView, refreshUnreadCount } from "./views/alerts.js";
import { CampaignView, CampaignsView } from "./views/campaigns.js";
import { CasesView } from "./views/cases.js";
import { DashboardView } from "./views/dashboard.js";
import { EmailView } from "./views/email/index.js";

/** @typedef {import('./types.js').Health} Health */

const MAX_TOAST_SUBJECT = 60;

const NAV = [
  ["dashboard", "🏠", "Home", "#/dashboard"],
  ["cases", "📥", "Checked emails", "#/cases"],
  ["campaigns", "🔗", "Linked attacks", "#/campaigns"],
  ["alerts", "🔔", "Alerts", "#/alerts"],
];

/**
 * @param {{ count: number }} props
 */
function UnreadBadge({ count }) {
  if (count <= 0) return null;
  return html`<span class="chip chip--count">${count}</span>`;
}

/**
 * @param {{ route: string, unread: number }} props
 */
function Rail({ route, unread }) {
  return html`<nav class="rail" aria-label="Main">
    <a class="rail__brand" href="#/dashboard">
      <span class="brand-mark">M</span>
      <span><span class="brand-name">MailTrace</span><span class="brand-sub">Email threat forensics</span></span>
    </a>
    ${NAV.map(
      ([name, icon, label, href]) => html`<a key=${name} class=${`rail__link${route === name ? " is-active" : ""}`} href=${href}>
        <span>${icon}</span><span>${label}</span>${name === "alerts" && html`<${UnreadBadge} count=${unread} />`}
      </a>`,
    )}
    <div class="rail__footer">SIH PS 26106<br />AI email threat detection, geolocation & forensics</div>
  </nav>`;
}

/**
 * @param {{ health: Health | null }} props
 */
function NetworkBadge({ health }) {
  if (!health) return html`<span class="chip">Server not reachable</span>`;
  return html`<span
    class="chip"
    title=${health.network
      ? "Location, domain age and blocklist checks are working"
      : "No location or domain-age data will be collected"}
  >
    <span class=${`status-dot tone-${health.network ? "ok" : "warn"}`}></span>
    ${health.network ? "Internet lookups on" : "Offline mode"}
  </span>`;
}

/**
 * @param {{ health: Health | null, unread: number, onMaskChange: () => void }} props
 */
function TopBar({ health, unread, onMaskChange }) {
  const [query, setQuery] = useState(session.listFilters.q);
  const [mask, setMask] = useState(preferences.mask);

  const toggleMask = () => {
    const next = !mask;
    setPreference("mask", next);
    setMask(next);
    toast(next ? "Personal details are now hidden everywhere." : "Personal details are shown again.");
    onMaskChange();
  };

  return html`<header class="topbar">
    <form
      class="topbar__search"
      role="search"
      onSubmit=${(/** @type {SubmitEvent} */ event) => {
        event.preventDefault();
        session.listFilters = { ...session.listFilters, q: query.trim(), page: 0 };
        navigate("#/cases");
      }}
    >
      <input
        class="input"
        value=${query}
        placeholder="Search by subject, sender, IP address or domain…"
        autoComplete="off"
        aria-label="Search checked emails"
        onChange=${(/** @type {{ target: HTMLInputElement }} */ event) => setQuery(event.target.value)}
      />
    </form>
    <div class="topbar__tools">
      <${NetworkBadge} health=${health} />
      <label
        class="switch-label topbar__mask"
        title="Hides names, email addresses, phone numbers and ID numbers everywhere on screen"
      >
        <span>Hide personal info</span>
        <span
          class=${`switch${mask ? " is-on" : ""}`}
          role="switch"
          tabIndex=${0}
          aria-checked=${String(mask)}
          aria-label="Hide personal information"
          onClick=${toggleMask}
          onKeyDown=${(/** @type {KeyboardEvent} */ event) => {
            if (event.key === " " || event.key === "Enter") {
              event.preventDefault();
              toggleMask();
            }
          }}
        ></span>
      </label>
      <a href="#/alerts" class="btn btn--icon topbar__bell" title="Alerts">🔔<${UnreadBadge} count=${unread} /></a>
    </div>
  </header>`;
}

/**
 * @param {{ route: { name: string, param: string } }} props
 */
function CurrentView({ route }) {
  switch (route.name) {
    case "cases":
      return html`<${CasesView} />`;
    case "email":
      return html`<${EmailView} emailId=${route.param} />`;
    case "campaigns":
      return route.param ? html`<${CampaignView} campaignId=${route.param} />` : html`<${CampaignsView} />`;
    case "alerts":
      return html`<${AlertsView} />`;
    default:
      return html`<${DashboardView} />`;
  }
}

function App() {
  const route = useRoute();
  const unread = useStore(unreadAlerts);
  const [health, setHealth] = useState(/** @type {Health | null} */ (null));
  const [maskEpoch, setMaskEpoch] = useState(0);

  useEffect(() => {
    api
      .health()
      .then((current) => {
        session.health = current;
        setHealth(current);
      })
      .catch(() => setHealth(null));
    void refreshUnreadCount();
  }, []);

  useEffect(
    () =>
      subscribeToAlerts((alert) => {
        unreadAlerts.set((count) => count + 1);
        toast(
          html`<${Fragment}>
            <b>${categoryOf(alert.category).label}</b> · risk ${alert.risk_score}<br />
            <a class="link" href=${`#/email/${encodeURIComponent(alert.email_id)}`}>
              ${truncate(alert.subject, MAX_TOAST_SUBJECT) || "Open it"}
            </a>
          </>`,
          "alert",
        );
      }),
    [],
  );

  return html`<${Fragment}>
    <div class="app">
      <${Rail} route=${route.name} unread=${unread} />
      <div class="app__main">
        <${TopBar}
          health=${health}
          unread=${unread}
          onMaskChange=${() => {
            resyncMask();
            setMaskEpoch((value) => value + 1);
          }}
        />
        <main class="view">
          <${CurrentView} key=${`${route.name}/${route.param}/${maskEpoch}`} route=${route} />
        </main>
      </div>
    </div>
    <${Toasts} />
  </>`;
}

const container = document.getElementById("root");
if (!container) throw new Error("#root is missing from index.html");
ReactDOM.createRoot(container).render(html`<${App} />`);
