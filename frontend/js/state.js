// @ts-check
/**
 * `preferences` survive a reload (localStorage); `session` lives for the page.
 *
 * Both are plain objects the views read directly: at this size a store with
 * subscriptions would be ceremony, not clarity. The one exception is the unread
 * alert count, which the live feed writes and three parts of the shell display,
 * so it is a tiny observable store instead.
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

/** @type {{ health: Health | null, listFilters: ListFilters, emailTab: EmailTab }} */
export const session = {
  health: null,
  listFilters: { q: "", category: "", minRisk: 0, page: 0 },
  emailTab: "findings",
};

/**
 * The unread alert count: written by the live feed and by the alerts view,
 * read by the bell, the rail badge and the alerts view itself.
 */
function createUnreadStore() {
  let count = 0;
  /** @type {Set<() => void>} */
  const listeners = new Set();
  return {
    get: () => count,
    /** @param {number | ((previous: number) => number)} next */
    set(next) {
      const value = typeof next === "function" ? next(count) : next;
      if (value === count) return;
      count = value;
      for (const listener of listeners) listener();
    },
    /** @param {() => void} listener */
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export const unreadAlerts = createUnreadStore();
