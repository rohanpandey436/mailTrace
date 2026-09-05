// @ts-check
/**
 * Pure formatting functions.  No DOM, no state, no side effects.
 */

const KILOBYTE = 1024;
const MEGABYTE = KILOBYTE * KILOBYTE;
const REGIONAL_INDICATOR_BASE = 0x1f1e6;

/**
 * @param {string | null | undefined} iso
 * @returns {string}
 */
export function formatDate(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

/**
 * @param {number | null | undefined} bytes
 * @returns {string}
 */
export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < KILOBYTE) return `${bytes} B`;
  if (bytes < MEGABYTE) return `${(bytes / KILOBYTE).toFixed(1)} KB`;
  return `${(bytes / MEGABYTE).toFixed(1)} MB`;
}

/**
 * A 0-1 ratio as a whole percentage.
 * @param {number | null | undefined} ratio
 */
export function percent(ratio) {
  return `${Math.round((ratio ?? 0) * 100)}%`;
}

/**
 * Clamp a number into 0-100.
 * @param {number | null | undefined} value
 */
export function clampPercent(value) {
  return Math.max(0, Math.min(100, value ?? 0));
}

/**
 * @param {string | null | undefined} text
 * @param {number} max
 */
export function truncate(text, max) {
  const value = text ?? "";
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/**
 * @param {number} count
 * @param {string} noun
 * @param {string} [plural]
 */
export function plural(count, noun, plural = `${noun}s`) {
  return `${count} ${count === 1 ? noun : plural}`;
}

/**
 * A two-letter country code as its flag emoji, or nothing.
 * @param {string | null | undefined} countryCode
 */
export function flag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return "";
  const points = Array.from(countryCode.toUpperCase(), (char) => REGIONAL_INDICATOR_BASE + char.charCodeAt(0) - 65);
  return String.fromCodePoint(...points);
}

/**
 * "City, Country" from whatever parts are present.
 * @param {Array<string | null | undefined>} parts
 */
export function place(parts) {
  return parts.filter(Boolean).join(", ");
}

/**
 * A signed weight to three decimals, always with a sign.
 * @param {number} weight
 */
export function signed(weight) {
  return `${weight >= 0 ? "+" : ""}${weight.toFixed(3)}`;
}

/**
 * @param {string} value
 */
export function decodeSegment(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
