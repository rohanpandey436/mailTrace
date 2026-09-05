// @ts-check
/**
 * Read design tokens from css/tokens.css at runtime.
 *
 * The map and the graph are drawn by libraries that take colour values, not
 * class names.  They get those values from here, so the stylesheet stays the
 * single source of truth for the palette.
 */

/** @type {Map<string, string>} */
const cache = new Map();

/**
 * The value of `--color-<name>`, e.g. `color("brand")`.
 * @param {string} name
 * @returns {string}
 */
export function color(name) {
  const cached = cache.get(name);
  if (cached) return cached;
  const value = getComputedStyle(document.documentElement).getPropertyValue(`--color-${name}`).trim();
  if (!value) throw new Error(`unknown colour token: --color-${name}`);
  cache.set(name, value);
  return value;
}

/**
 * The strong colour of a tone, e.g. `toneColor("bad")`.
 * @param {import('./labels.js').Tone} tone
 */
export function toneColor(tone) {
  return color(tone === "ink" ? "ink" : tone);
}
