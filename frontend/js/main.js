import { UNREACHABLE_EVENT, api } from "./api.js";
import { truncate } from "./format.js";
import { useOnline, useStore } from "./hooks.js";
import { categoryOf } from "./labels.js";
import { resyncMask, subscribeToAlerts } from "./live-feed.js";
import { Fragment, html, useEffect, useRef, useState } from "./react.js";
import { navigate, useRoute } from "./router.js";
import { preferences, session, setPreference, unreadAlerts } from "./state.js";
import { Toasts, toast } from "./ui/toast.js";
import { AlertsView, refreshUnreadCount } from "./views/alerts.js";
import { CampaignView, CampaignsView } from "./views/campaigns.js";
import { CasesView } from "./views/cases.js";
import { DashboardView } from "./views/dashboard.js";
import { EmailView } from "./views/email/index.js";

const MAX_TOAST_SUBJECT = 60;
const HEALTH_RETRY_MS = 10000;

const NAV = [
  ["dashboard", "🏠", "Home", "#/dashboard"],
  ["cases", "📥", "Checked emails", "#/cases"],
  ["campaigns", "🔗", "Linked attacks", "#/campaigns"],
  ["alerts", "🔔", "Alerts", "#/alerts"],
];

function UnreadBadge({ count }) {
  if (count <= 0) return null;
  return html`<span class="chip chip--count">${count}</span>`;
}

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

function NetworkBadge({ health, checking }) {
  if (!health) {
    return html`<span class="chip" title="MailTrace keeps trying to reach the server">
      <span class=${`status-dot tone-bad${checking ? " is-pulsing" : ""}`}></span>
      ${checking ? "Reconnecting…" : "Server not reachable"}
    </span>`;
  }
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

function ConnectionBanner({ online, reachable, checking, onRetry }) {
  if (online && reachable) return null;
  const text = online
    ? "Can't reach the MailTrace server. It may be waking up; MailTrace retries every few seconds."
    : "You are offline. MailTrace needs an internet connection to check emails and open cases.";
  return html`<div class=${`banner ${online ? "banner--warn" : "banner--bad"}`} role="status" aria-live="polite">
    <span class=${`status-dot tone-${online ? "warn" : "bad"} is-pulsing`}></span>
    <span class="spread">${text}</span>
    ${online && html`<button class=${`btn${checking ? " is-busy" : ""}`} type="button" onClick=${onRetry}>Try again</button>`}
  </div>`;
}

function TopBar({ health, checking, unread, onMaskChange }) {
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
      onSubmit=${(event) => {
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
        onChange=${(event) => setQuery(event.target.value)}
      />
    </form>
    <div class="topbar__tools">
      <${NetworkBadge} health=${health} checking=${checking} />
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
          onKeyDown=${(event) => {
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

function useServerHealth(online) {
  const [health, setHealth] = useState((null));
  const [reachable, setReachable] = useState(true);
  const [checking, setChecking] = useState(true);
  const [epoch, setEpoch] = useState(0);
  const [recoveries, setRecoveries] = useState(0);
  const wasReachable = useRef(true);

  useEffect(() => {
    const recheck = () => {
      if (wasReachable.current) setEpoch((value) => value + 1);
    };
    window.addEventListener(UNREACHABLE_EVENT, recheck);
    return () => window.removeEventListener(UNREACHABLE_EVENT, recheck);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer = 0;
    const check = async () => {
      setChecking(true);
      try {
        const current = await api.health();
        if (cancelled) return;
        session.health = current;
        setHealth(current);
        setReachable(true);
        if (!wasReachable.current) {
          toast("Connected to the server again.");
          setRecoveries((value) => value + 1);
        }
        wasReachable.current = true;
      } catch {
        if (cancelled) return;
        setHealth(null);
        setReachable(false);
        wasReachable.current = false;
        timer = window.setTimeout(() => void check(), HEALTH_RETRY_MS);
      } finally {
        if (!cancelled) setChecking(false);
      }
    };
    void check();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [epoch, online]);

  return { health, reachable, checking, recoveries, retry: () => setEpoch((value) => value + 1) };
}

function App() {
  const route = useRoute();
  const unread = useStore(unreadAlerts);
  const online = useOnline();
  const { health, reachable, checking, recoveries, retry } = useServerHealth(online);
  const [maskEpoch, setMaskEpoch] = useState(0);

  useEffect(() => {
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
          checking=${checking}
          unread=${unread}
          onMaskChange=${() => {
            resyncMask();
            setMaskEpoch((value) => value + 1);
          }}
        />
        <${ConnectionBanner} online=${online} reachable=${reachable} checking=${checking} onRetry=${retry} />
        <main class="view">
          <div class="view__content" key=${`${route.name}/${route.param}/${maskEpoch}/${recoveries}`}>
            <${CurrentView} route=${route} />
          </div>
        </main>
      </div>
    </div>
    <${Toasts} />
  </>`;
}

const container = document.getElementById("root");
if (!container) throw new Error("#root is missing from index.html");
ReactDOM.createRoot(container).render(html`<${App} />`);
