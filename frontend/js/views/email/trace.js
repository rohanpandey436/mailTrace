// @ts-check
/** "Where it came from": the Received chain as a list, and the same hops on a map. */
import { $$, html, must } from "../../dom.js";
import { flag, formatDate, place } from "../../format.js";
import { createRouteMap } from "../../ui/map.js";
import { chip } from "../../ui/primitives.js";

/** @typedef {import('../../types.js').AnalysisResult} AnalysisResult */
/** @typedef {import('../../types.js').GeoInfo} GeoInfo */
/** @typedef {import('../../types.js').Health} Health */
/** @typedef {import('../../types.js').Hop} Hop */

/**
 * @param {number | null} seconds
 */
function delay(seconds) {
  if (seconds === null) return null;
  if (seconds < 0) return html`<span class="text-bad strong">clock went backwards</span>`;
  return html`<span>took ${Math.round(seconds)}s</span>`;
}

/**
 * @param {GeoInfo | null} geo
 */
function location(geo) {
  if (!geo || (!geo.country && !geo.isp)) return null;
  return html`<div class="hop__geo">
    ${flag(geo.country_code)} ${place([geo.city, geo.country])}${geo.isp ? ` · ${geo.isp}` : ""}
    ${geo.is_tor_exit && chip("Tor", "bad")}
    ${geo.blacklists.length > 0 && chip("on a blocklist", "bad")}
  </div>`;
}

/**
 * @param {Hop} hop
 * @param {boolean} origin
 */
function hopRow(hop, origin) {
  return html`<div class="hop${origin ? " is-origin" : ""}" data-hop="${hop.index}">
    <div class="hop__head">
      <span class="mono muted">Step ${hop.index + 1}</span>
      ${origin && chip("STARTED HERE", "brand")}
      <b class="truncate">${hop.from_host || hop.from_ip || "unknown computer"}</b>
      ${hop.is_private_ip && chip("inside a private network")}
    </div>
    <div class="hint hop__meta">
      <span class="mono">${hop.from_ip || "no address"}</span>
      <span>handed to ${hop.by_host || "unknown"}</span>
      <span>${formatDate(hop.timestamp)}</span>
      ${delay(hop.delay_seconds)}
    </div>
    ${location(hop.geo)}
  </div>`;
}

/**
 * Why the map is empty, in the user's terms rather than the engine's.
 * @param {number} hops
 * @param {number} located
 * @param {Health | null} health
 */
function mapNote(hops, located, health) {
  if (located > 0) return "Pins follow the order on the left. The orange pin is where the email started.";
  if (hops === 0) return "Nothing to map: the email had no delivery headers.";
  if (health && !health.network) {
    return "No pins because internet lookups are switched off. Restart without MAILTRACE_ENABLE_NETWORK=false and check the email again.";
  }
  return "No pins: every step used a private or unlisted address, so no location could be found.";
}

/**
 * @param {AnalysisResult} result
 * @param {Health | null} health
 */
export function traceTab(result, health) {
  const { hops, originating_hop_index: originIndex, origin_reasoning: reasoning } = result.headers;
  const located = hops.filter((hop) => hop.geo !== null && hop.geo.lat !== null).length;
  const path =
    hops.length > 0
      ? html`<div class="hops">${hops.map((hop) => hopRow(hop, hop.index === originIndex))}</div>`
      : html`<div class="hint">This email carried no delivery record, so there is no path to show.</div>`;
  return html`<div class="grid grid--2">
    <section class="card card--pad">
      <h3 class="section__title">The journey this email took</h3>
      <p class="hint section__note">Read top to bottom. Each step is one mail server passing it along. ${reasoning}</p>
      ${path}
    </section>
    <section class="card card--pad">
      <h3 class="section__title">On the map</h3>
      <p class="hint section__note">${mapNote(hops.length, located, health)}</p>
      <div id="map" class="map"></div>
    </section>
  </div>`;
}

/**
 * Links the hop list to the map pins in both directions.
 * @param {HTMLElement} panel
 * @param {AnalysisResult} result
 * @returns {() => void} cleanup
 */
export function mountRouteMap(panel, result) {
  const rows = $$(".hop[data-hop]", panel);
  /** @param {number} index */
  const highlight = (index) => rows.forEach((row) => row.classList.toggle("is-active", Number(row.dataset.hop) === index));
  const map = createRouteMap(must("#map", panel), result.headers.hops, result.headers.originating_hop_index, highlight);
  for (const row of rows) {
    row.addEventListener("click", () => {
      const index = Number(row.dataset.hop);
      highlight(index);
      map.focus(index);
    });
  }
  return map.destroy;
}
