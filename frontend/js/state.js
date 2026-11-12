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

function createStore(initial) {
  let current = initial;
  const listeners = new Set();
  return {
    get: () => current,
    set(next) {
      const value = typeof next === "function" ? next(current) : next;
      if (value === current) return;
      current = value;
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export const unreadAlerts = createStore(0);

export const pageSections = createStore({ items: [], active: "" });
