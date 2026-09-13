const KILOBYTE = 1024;
const MEGABYTE = KILOBYTE * KILOBYTE;
const REGIONAL_INDICATOR_BASE = 0x1f1e6;

export function formatDate(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < KILOBYTE) return `${bytes} B`;
  if (bytes < MEGABYTE) return `${(bytes / KILOBYTE).toFixed(1)} KB`;
  return `${(bytes / MEGABYTE).toFixed(1)} MB`;
}

export function percent(ratio) {
  return `${Math.round((ratio ?? 0) * 100)}%`;
}

export function clampPercent(value) {
  return Math.max(0, Math.min(100, value ?? 0));
}

export function truncate(text, max) {
  const value = text ?? "";
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function plural(count, noun, plural = `${noun}s`) {
  return `${count} ${count === 1 ? noun : plural}`;
}

export function flag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return "";
  const points = Array.from(countryCode.toUpperCase(), (char) => REGIONAL_INDICATOR_BASE + char.charCodeAt(0) - 65);
  return String.fromCodePoint(...points);
}

export function place(parts) {
  return parts.filter(Boolean).join(", ");
}

export function signed(weight) {
  return `${weight >= 0 ? "+" : ""}${weight.toFixed(3)}`;
}

export function decodeSegment(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
