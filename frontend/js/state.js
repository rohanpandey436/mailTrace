// @ts-check
/**
 * `preferences` survive a reload (localStorage); `session` lives for the page.
 *
 * Both are plain objects the views read directly: at this size a store with
 * subscriptions would be ceremony, not clarity.
 */

/** @typedef {import('./types.js').Health} Health */
/** @typedef {'findings' | 'trace' | 'content' | 'links' | 'domains' | 'graph' | 'custody'} EmailTab */
/** @typedef {{ q: string, category: string, minRisk: number, page: number }} ListFilters */

const STORAGE_KEYS = { mask: "mailtrace.mask", advanced: "mailtrace.advanced" };

/**
 * @param {keyof typeof STORAGE_KEYS} key
 */
function readFlag(key) {
  try {
    return localStorage.getItem(STORAGE_KEYS[key]) === "1";
  } catch {
    return false;
  }
}

/**
 * @param {keyof typeof STORAGE_KEYS} key
 * @param {boolean} value
 */
function writeFlag(key, value) {
  try {
    localStorage.setItem(STORAGE_KEYS[key], value ? "1" : "0");
  } catch {
    // Private mode or storage disabled: the preference simply does not persist.
  }
}

export const preferences = {
  /** Hide names, addresses and ID numbers everywhere on screen. */
  mask: readFlag("mask"),
  /** Show the connection graph and the evidence log tabs. */
  advanced: readFlag("advanced"),
};

/**
 * @param {keyof typeof preferences} key
 * @param {boolean} value
 */
export function setPreference(key, value) {
  preferences[key] = value;
  writeFlag(key, value);
}

/** @type {{ health: Health | null, unreadAlerts: number, listFilters: ListFilters, emailTab: EmailTab }} */
export const session = {
  health: null,
  unreadAlerts: 0,
  listFilters: { q: "", category: "", minRisk: 0, page: 0 },
  emailTab: "findings",
};
