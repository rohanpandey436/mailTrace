const cache = new Map();

export function color(name) {
  const cached = cache.get(name);
  if (cached) return cached;
  const value = getComputedStyle(document.documentElement).getPropertyValue(`--color-${name}`).trim();
  if (!value) throw new Error(`unknown colour token: --color-${name}`);
  cache.set(name, value);
  return value;
}

export function toneColor(tone) {
  return color(tone === "ink" ? "ink" : tone);
}
