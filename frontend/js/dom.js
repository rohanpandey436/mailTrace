// @ts-check
/**
 * HTML escaping for the one place React does not reach.
 *
 * React escapes everything it renders, so the application needs none of this.
 * Leaflet is the exception: `bindPopup` takes a string of markup and builds its
 * own DOM outside React, so the values interpolated into a popup have to be
 * escaped by hand.
 */

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/**
 * Escape a value for insertion into HTML text or an attribute value.
 * @param {unknown} value
 * @returns {string}
 */
export function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (char) => ESCAPES[/** @type {keyof ESCAPES} */ (char)]);
}
