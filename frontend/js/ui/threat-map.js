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

function toneOf(origin) {
  return severityOf(severityForScore(origin.max_risk)).tone;
}

function nameOf(origin) {
  return place([origin.city, origin.country]) || origin.ip;
}

function showEmails(origin) {
  setListFilters({ q: origin.ip, category: "", minRisk: 0, page: 0 });
  navigate("#/cases");
}

function popup(origin) {
  const node = document.createElement("div");
  node.className = "map-popup";
  const title = document.createElement("b");
  title.textContent = nameOf(origin);
  const address = document.createElement("div");
  address.className = "mono";
  address.textContent = origin.ip;
  const count = document.createElement("div");
  count.textContent = `${plural(origin.emails, "email")} · worst risk ${origin.max_risk}`;
  const open = document.createElement("button");
  open.type = "button";
  open.className = "linkbtn";
  open.textContent = origin.emails === 1 ? "See this email" : "See these emails";
  open.addEventListener("click", () => showEmails(origin));
  node.append(title, address, count, open);
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
    const points = origins.map((origin) => ([origin.lat, origin.lon]));
    for (const origin of origins) {
      L.circleMarker([origin.lat, origin.lon], {
        radius: BASE_RADIUS + Math.min(MAX_EXTRA_RADIUS, Math.sqrt(origin.emails) * RADIUS_STEP),
        color: color("card"),
        weight: 2,
        fillColor: color(toneOf(origin)),
        fillOpacity: 0.9,
      })
        .addTo(map)
        .bindPopup(popup(origin));
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
  const emails = origins.reduce((sum, origin) => sum + origin.emails, 0);
  return html`<div class="origins">
    <div class="origins__total">
      <b class="strong">${plural(emails, "email")}</b> traced to <b class="strong">${plural(origins.length, "place")}</b>
    </div>
    <div class="stack">
      ${origins.slice(0, LIST_LIMIT).map(
        (origin) => html`<div key=${origin.ip} class="dist__row">
          <span class=${`dot tone-${toneOf(origin)}`}></span><span class="spread truncate" title=${origin.ip}>${nameOf(origin)}</span><b>${origin.emails}</b>
        </div>`,
      )}
    </div>
    ${origins.length > LIST_LIMIT && html`<div class="hint origins__more">and ${plural(origins.length - LIST_LIMIT, "more place")} on the map</div>`}
  </div>`;
}
