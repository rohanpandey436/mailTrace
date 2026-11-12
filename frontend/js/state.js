const STORAGE_KEYS = { mask: "mailtrace.mask" };

function readFlag(key) {
  try {
    return localStorage.getItem(STORAGE_KEYS[key]) === "1";
  } catch {
    return false;
  }
}

function writeFlag(key, value) {
  try {
    localStorage.setItem(STORAGE_KEYS[key], value ? "1" : "0");
  } catch {
  }
}

export const preferences = {
  mask: readFlag("mask"),
};

export function setPreference(key, value) {
  preferences[key] = value;
  writeFlag(key, value);
}

export const session = {
  health: null,
  listFilters: { q: "", category: "", minRisk: 0, page: 0 },
  emailTab: "findings",
  showLesserFindings: false,
};

const filterListeners = new Set();

export function setListFilters(next) {
  session.listFilters = next;
  for (const listener of filterListeners) listener(next);
}

export function onListFilters(listener) {
  filterListeners.add(listener);
  return () => {
    filterListeners.delete(listener);
  };
}

function createUnreadStore() {
  let count = 0;
  const listeners = new Set();
  return {
    get: () => count,
    set(next) {
      const value = typeof next === "function" ? next(count) : next;
      if (value === count) return;
      count = value;
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export const unreadAlerts = createUnreadStore();
