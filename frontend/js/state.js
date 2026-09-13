const STORAGE_KEYS = { mask: "mailtrace.mask", advanced: "mailtrace.advanced" };

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
  advanced: readFlag("advanced"),
};

export function setPreference(key, value) {
  preferences[key] = value;
  writeFlag(key, value);
}

export const session = {
  health: null,
  listFilters: { q: "", category: "", minRisk: 0, page: 0 },
  emailTab: "findings",
};

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
