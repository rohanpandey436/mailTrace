// @ts-check
/**
 * The delivery-path map: one pin per located hop, joined in delivery order.
 *
 * Leaflet takes colour values rather than classes, so they come from the
 * design tokens through theme.js.
 */
import { esc } from "../dom.js";
import { place } from "../format.js";
import { color } from "../theme.js";

/** @typedef {import('../types.js').Hop} Hop */

const TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
const ATTRIBUTION = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';
const TILE_MAX_ZOOM = 18;
/** Where the map rests when nothing could be located. */
const WORLD_CENTRE = /** @type {L.LatLngTuple} */ ([22, 20]);
const WORLD_ZOOM = 2;
/**
 * A single location would otherwise zoom to street level, which looks broken
 * and implies a precision IP geolocation does not have.  Keep it country-scale.
 */
const SINGLE_POINT_ZOOM = 5;
const FIT_MAX_ZOOM = 8;
const FIT_PADDING = 0.35;
const ORIGIN_RADIUS = 10;
const HOP_RADIUS = 7;
/** Leaflet measures its container once; give the layout a moment to settle first. */
const LAYOUT_SETTLE_MS = 60;

/**
 * @typedef {object} RouteMap
 * @property {(index: number) => void} focus pan to a hop's pin and open its popup
 * @property {() => void} destroy
 */

/**
 * @param {Hop} hop
 * @param {boolean} origin
 */
function popup(hop, origin) {
  const geo = hop.geo;
  return `<div class="map-popup"><b>Step ${hop.index + 1}${origin ? " · started here" : ""}</b><br>${esc(hop.from_ip)}<br>${esc(
    place([geo?.city, geo?.country]),
  )}<br>${esc(geo?.isp)}</div>`;
}

/**
 * @param {HTMLElement} container
 * @param {Hop[]} hops
 * @param {number | null} originIndex
 * @param {(index: number) => void} onSelect called when a pin is clicked
 * @returns {RouteMap}
 */
export function createRouteMap(container, hops, originIndex, onSelect) {
  const map = L.map(container, { zoomControl: true, scrollWheelZoom: false });
  L.tileLayer(TILE_URL, { attribution: ATTRIBUTION, maxZoom: TILE_MAX_ZOOM }).addTo(map);

  /** @type {Array<{ hop: Hop, point: L.LatLngTuple }>} */
  const located = [];
  for (const hop of hops) {
    if (hop.geo && hop.geo.lat !== null && hop.geo.lon !== null) located.push({ hop, point: [hop.geo.lat, hop.geo.lon] });
  }
  /** @type {Map<number, L.CircleMarker>} */
  const pins = new Map();

  if (located.length === 0) {
    map.setView(WORLD_CENTRE, WORLD_ZOOM);
  } else {
    const points = located.map((entry) => entry.point);
    if (points.length > 1) {
      L.polyline(points, { color: color("brand"), weight: 2, dashArray: "6 6", opacity: 0.75 }).addTo(map);
    }
    for (const { hop, point } of located) {
      const origin = hop.index === originIndex;
      const pin = L.circleMarker(point, {
        radius: origin ? ORIGIN_RADIUS : HOP_RADIUS,
        color: color("card"),
        weight: 2,
        fillColor: origin ? color("brand") : color("info"),
        fillOpacity: 0.95,
      }).addTo(map);
      pin.bindPopup(popup(hop, origin));
      pin.on("click", () => onSelect(hop.index));
      pins.set(hop.index, pin);
    }
    if (points.length === 1) map.setView(points[0], SINGLE_POINT_ZOOM);
    else map.fitBounds(L.latLngBounds(points).pad(FIT_PADDING), { maxZoom: FIT_MAX_ZOOM });
  }
  setTimeout(() => map.invalidateSize(), LAYOUT_SETTLE_MS);

  return {
    focus(index) {
      const pin = pins.get(index);
      if (!pin) return;
      map.panTo(pin.getLatLng());
      pin.openPopup();
    },
    destroy() {
      map.remove();
    },
  };
}
