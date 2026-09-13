import { esc } from "../dom.js";
import { place } from "../format.js";
import { html, useEffect, useRef } from "../react.js";
import { color } from "../theme.js";

const TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
const ATTRIBUTION = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';
const TILE_MAX_ZOOM = 18;
const WORLD_CENTRE = ([22, 20]);
const WORLD_ZOOM = 2;
const SINGLE_POINT_ZOOM = 5;
const FIT_MAX_ZOOM = 8;
const FIT_PADDING = 0.35;
const ORIGIN_RADIUS = 10;
const HOP_RADIUS = 7;
const LAYOUT_SETTLE_MS = 60;

function popup(hop, origin) {
  const geo = hop.geo;
  return `<div class="map-popup"><b>Step ${hop.index + 1}${origin ? " · started here" : ""}</b><br>${esc(hop.from_ip)}<br>${esc(
    place([geo?.city, geo?.country]),
  )}<br>${esc(geo?.isp)}</div>`;
}

export function RouteMap({ hops, originIndex, selected, onSelect }) {
  const container = useRef((null));
  const map = useRef((null));
  const pins = useRef((new Map()));
  const select = useRef(onSelect);
  select.current = onSelect;

  useEffect(() => {
    const element = container.current;
    if (!element || typeof L === "undefined") return undefined;

    const instance = L.map(element, { zoomControl: true, scrollWheelZoom: false });
    map.current = instance;
    pins.current = new Map();
    L.tileLayer(TILE_URL, { attribution: ATTRIBUTION, maxZoom: TILE_MAX_ZOOM }).addTo(instance);

    const located = [];
    for (const hop of hops) {
      if (hop.geo && hop.geo.lat !== null && hop.geo.lon !== null) located.push({ hop, point: [hop.geo.lat, hop.geo.lon] });
    }

    if (located.length === 0) {
      instance.setView(WORLD_CENTRE, WORLD_ZOOM);
    } else {
      const points = located.map((entry) => entry.point);
      if (points.length > 1) {
        L.polyline(points, { color: color("brand"), weight: 2, dashArray: "6 6", opacity: 0.75 }).addTo(instance);
      }
      for (const { hop, point } of located) {
        const origin = hop.index === originIndex;
        const pin = L.circleMarker(point, {
          radius: origin ? ORIGIN_RADIUS : HOP_RADIUS,
          color: color("card"),
          weight: 2,
          fillColor: origin ? color("brand") : color("info"),
          fillOpacity: 0.95,
        }).addTo(instance);
        pin.bindPopup(popup(hop, origin));
        pin.on("click", () => select.current(hop.index));
        pins.current.set(hop.index, pin);
      }
      if (points.length === 1) instance.setView(points[0], SINGLE_POINT_ZOOM);
      else instance.fitBounds(L.latLngBounds(points).pad(FIT_PADDING), { maxZoom: FIT_MAX_ZOOM });
    }
    const settle = setTimeout(() => instance.invalidateSize(), LAYOUT_SETTLE_MS);

    return () => {
      clearTimeout(settle);
      instance.remove();
      map.current = null;
      pins.current = new Map();
    };
  }, [hops, originIndex]);

  useEffect(() => {
    if (selected === null) return;
    const pin = pins.current.get(selected);
    if (!pin || !map.current) return;
    map.current.panTo(pin.getLatLng());
    pin.openPopup();
  }, [selected]);

  return html`<div class="map" ref=${container}></div>`;
}
