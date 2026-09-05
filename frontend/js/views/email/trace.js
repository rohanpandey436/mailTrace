// @ts-check
/** "Where it came from": the Received chain as a list, and the same hops on a map. */
import { flag, formatDate, place } from "../../format.js";
import { html, useState } from "../../react.js";
import { session } from "../../state.js";
import { RouteMap } from "../../ui/map.js";
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
    ${geo.is_tor_exit && chip("Tor", "bad")} ${geo.blacklists.length > 0 && chip("on a blocklist", "bad")}
  </div>`;
}

/**
 * @param {{ hop: Hop, origin: boolean, active: boolean, onSelect: () => void }} props
 */
function HopRow({ hop, origin, active, onSelect }) {
  return html`<div class=${`hop${origin ? " is-origin" : ""}${active ? " is-active" : ""}`} onClick=${onSelect}>
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
 * @param {{ result: AnalysisResult }} props
 */
export function TraceTab({ result }) {
  const { hops, originating_hop_index: originIndex, origin_reasoning: reasoning } = result.headers;
  // One piece of state drives both panes, so clicking either highlights both.
  const [selected, setSelected] = useState(/** @type {number | null} */ (null));
  const located = hops.filter((hop) => hop.geo !== null && hop.geo.lat !== null).length;

  return html`<div class="grid grid--2">
    <section class="card card--pad">
      <h3 class="section__title">The journey this email took</h3>
      <p class="hint section__note">Read top to bottom. Each step is one mail server passing it along. ${reasoning}</p>
      ${hops.length > 0
        ? html`<div class="hops">
            ${hops.map(
              (hop) => html`<${HopRow}
                key=${hop.index}
                hop=${hop}
                origin=${hop.index === originIndex}
                active=${hop.index === selected}
                onSelect=${() => setSelected(hop.index)}
              />`,
            )}
          </div>`
        : html`<div class="hint">This email carried no delivery record, so there is no path to show.</div>`}
    </section>
    <section class="card card--pad">
      <h3 class="section__title">On the map</h3>
      <p class="hint section__note">${mapNote(hops.length, located, session.health)}</p>
      <${RouteMap} hops=${hops} originIndex=${originIndex} selected=${selected} onSelect=${setSelected} />
    </section>
  </div>`;
}
