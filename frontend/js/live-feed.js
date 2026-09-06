// @ts-check
import { urls } from "./api.js";
import { preferences } from "./state.js";

/** @typedef {import('./types.js').Alert} Alert */

/** Some proxies accept the upgrade and then never complete it. */
const HANDSHAKE_TIMEOUT_MS = 5000;

/** @type {Set<(alert: Alert) => void>} */
const listeners = new Set();
/** @type {(() => void) | null} */
let disconnect = null;
/** The mask setting the open connection was made with. */
let connectedMask = false;

/**
 * @param {unknown} value
 * @returns {value is Alert}
 */
function isAlert(value) {
  return typeof value === "object" && value !== null && "id" in value && "email_id" in value;
}

/** @param {string} text */
function deliver(text) {
  try {
    const data = JSON.parse(text);
    if (isAlert(data)) for (const listener of listeners) listener(data);
  } catch {
    // Not an alert frame; ignore it.
  }
}

/** @returns {() => void} */
function connect() {
  const mask = preferences.mask;
  connectedMask = mask;
  let stopped = false;
  /** @type {EventSource | null} */
  let source = null;
  /** @type {WebSocket | null} */
  let socket = null;

  const startSse = () => {
    if (stopped || source || !("EventSource" in window)) return;
    source = new EventSource(urls.alertStream(mask));
    source.addEventListener("alert", (event) => deliver(/** @type {MessageEvent<string>} */ (event).data));
  };

  const stop = () => {
    stopped = true;
    socket?.close();
    source?.close();
  };

  if (!("WebSocket" in window)) {
    startSse();
    return stop;
  }
  let opened = false;
  try {
    socket = new WebSocket(urls.alertSocket(mask));
  } catch {
    startSse();
    return stop;
  }
  const ws = socket;
  ws.onopen = () => {
    opened = true;
  };
  ws.onmessage = (event) => deliver(String(event.data));
  ws.onclose = () => startSse(); // never opened, or dropped later
  ws.onerror = () => {
    if (!opened) ws.close();
  };
  setTimeout(() => {
    if (!opened && ws.readyState !== WebSocket.OPEN) {
      ws.close();
      startSse();
    }
  }, HANDSHAKE_TIMEOUT_MS);
  return stop;
}

/**
 * Receive every alert until the returned function is called. The first
 * subscriber opens the connection; the last one to leave closes it.
 * @param {(alert: Alert) => void} listener
 * @returns {() => void}
 */
export function subscribeToAlerts(listener) {
  listeners.add(listener);
  if (!disconnect) disconnect = connect();
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      disconnect?.();
      disconnect = null;
    }
  };
}

/** Reconnect if the PII-mask preference has changed since the feed opened. */
export function resyncMask() {
  if (!disconnect || connectedMask === preferences.mask) return;
  disconnect();
  disconnect = listeners.size > 0 ? connect() : null;
}
