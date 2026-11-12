import { place, plural } from "../format.js";
import { useVendor } from "../hooks.js";
import { severityForScore, severityOf } from "../labels.js";
import { loadLeaflet } from "../libs.js";
import { html, useEffect, useRef } from "../react.js";
import { navigate } from "../router.js";
import { setListFilters } from "../state.js";
import { color } from "../theme.js";
import { ATTRIBUTION, TILE_MAX_ZOOM, TILE_URL } from "./map.js";

const WORLD_CENTRE = ([25, 15]);
const WORLD_ZOOM = 1;
const SINGLE_POINT_ZOOM = 4;
const FIT_MAX_ZOOM = 5;
const FIT_PADDING = 0.3;
const BASE_RADIUS = 7;
const RADIUS_STEP = 3;
const MAX_EXTRA_RADIUS = 13;
const LAYOUT_SETTLE_MS = 60;
const LIST_LIMIT = 6;
const POPUP_LIMIT = 4;

function toneOf(group) {
  return severityOf(severityForScore(group.max_risk)).tone;
}

function nameOf(origin) {
  return place([origin.city, origin.country]) || origin.ip;
}

function spotOf(origin) {
  return `${origin.lat},${origin.lon}`;
}

function grouped(origins, keyOf) {
  const groups = new Map();
  for (const origin of origins) {
    const key = keyOf(origin);
    const group = groups.get(key);
    if (group) {
      group.origins.push(origin);
      group.emails += origin.emails;
      group.max_risk = Math.max(group.max_risk, origin.max_risk);
    } else {
      groups.set(key, {
        name: nameOf(origin),
        lat: origin.lat,
        lon: origin.lon,
        origins: [origin],
        emails: origin.emails,
        max_risk: origin.max_risk,
      });
    }
  }
  return [...groups.values()].sort((a, b) => b.emails - a.emails || b.max_risk - a.max_risk);
}

function showEmails(origin) {
  setListFilters({ q: origin.ip, category: "", minRisk: 0, page: 0 });
  navigate("#/cases");
}

function emailsLink(origin, label) {
  const open = document.createElement("button");
  open.type = "button";
  open.className = "linkbtn";
  open.textContent = label;
  open.addEventListener("click", () => showEmails(origin));
  return open;
}

function popup(spot) {
  const node = document.createElement("div");
  node.className = "map-popup";
  const title = document.createElement("b");
  title.textContent = spot.name;
  const count = document.createElement("div");
  count.textContent = `${plural(spot.emails, "email")} · worst risk ${spot.max_risk}`;
  if (spot.origins.length === 1) {
    const [origin] = spot.origins;
    const address = document.createElement("div");
    address.className = "mono";
    address.textContent = origin.ip;
    node.append(title, address, count, emailsLink(origin, origin.emails === 1 ? "See this email" : "See these emails"));
    return node;
  }
  node.append(title, count);
  for (const origin of spot.origins.slice(0, POPUP_LIMIT)) {
    const row = document.createElement("div");
    row.append(emailsLink(origin, `${origin.ip}: ${plural(origin.emails, "email")}`));
    node.append(row);
  }
  if (spot.origins.length > POPUP_LIMIT) {
    const more = document.createElement("div");
    more.textContent = `and ${plural(spot.origins.length - POPUP_LIMIT, "more address", "more addresses")}`;
    node.append(more);
  }
  return node;
}

export function ThreatMap({ origins }) {
  const container = useRef((null));
  const library = useVendor(loadLeaflet);

  useEffect(() => {
    const element = container.current;
    if (!element || library !== "ready" || typeof L === "undefined") return undefined;

    const map = L.map(element, { zoomControl: true, scrollWheelZoom: false, worldCopyJump: true, minZoom: 1 });
    L.tileLayer(TILE_URL, { attribution: ATTRIBUTION, maxZoom: TILE_MAX_ZOOM }).addTo(map);
    const spots = grouped(origins, spotOf);
    const points = spots.map((spot) => ([spot.lat, spot.lon]));
    for (const spot of spots) {
      L.circleMarker([spot.lat, spot.lon], {
        radius: BASE_RADIUS + Math.min(MAX_EXTRA_RADIUS, Math.sqrt(spot.emails) * RADIUS_STEP),
        color: color("card"),
        weight: 2,
        fillColor: color(toneOf(spot)),
        fillOpacity: 0.9,
      })
        .addTo(map)
        .bindPopup(popup(spot));
    }
    if (points.length === 0) map.setView(WORLD_CENTRE, WORLD_ZOOM);
    else if (points.length === 1) map.setView(points[0], SINGLE_POINT_ZOOM);
    else map.fitBounds(L.latLngBounds(points).pad(FIT_PADDING), { maxZoom: FIT_MAX_ZOOM });
    const settle = setTimeout(() => map.invalidateSize(), LAYOUT_SETTLE_MS);

    return () => {
      clearTimeout(settle);
      map.remove();
    };
  }, [origins, library]);

  if (library === "failed") {
    return html`<div class="map map--threat map--note hint">The map could not be loaded. Check your internet connection and reload the page.</div>`;
  }
  return html`<div class=${`map map--threat${library === "loading" ? " is-loading" : ""}`} ref=${container}></div>`;
}

export function OriginList({ origins }) {
  const places = grouped(origins, nameOf);
  const emails = places.reduce((sum, entry) => sum + entry.emails, 0);
  return html`<div class="origins">
    <div class="origins__total">
      <b class="strong">${plural(emails, "email")}</b> traced to <b class="strong">${plural(places.length, "place")}</b>
    </div>
    <div class="stack">
      ${places.slice(0, LIST_LIMIT).map(
        (entry) => html`<div key=${entry.name} class="dist__row">
          <span class=${`dot tone-${toneOf(entry)}`}></span><span class="spread truncate" title=${entry.name}>${entry.name}</span><b>${entry.emails}</b>
        </div>`,
      )}
    </div>
    ${places.length > LIST_LIMIT && html`<div class="hint origins__more">and ${plural(places.length - LIST_LIMIT, "more place")} on the map</div>`}
  </div>`;
}
