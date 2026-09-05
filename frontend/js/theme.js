// @ts-check
/**
 * Read design tokens from css/tokens.css at runtime.
 *
 * The map and graph libraries take colour values, not class names. They read
 * them from here, so the stylesheet stays the only source of the palette.
 */

/** @type {Map<string, string>} */
const cache = new Map();

/**
 * `color("brand")` -> the value of `--color-brand`.
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
 * The strong (not the soft) colour of a tone.
 * @param {import('./labels.js').Tone} tone
 */
export function toneColor(tone) {
  return color(tone === "ink" ? "ink" : tone);
}
