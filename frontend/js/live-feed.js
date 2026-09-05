// @ts-check
/**
 * Live alerts.
 *
 * The WebSocket is preferred: it survives proxies that buffer
 * text/event-stream and does not count against the browser's per-origin SSE
 * limit. SSE takes over if the handshake fails or the socket drops later.
 * Both carry identical Alert JSON, so exactly one needs to be connected.
 */
import { urls } from "./api.js";
import { preferences } from "./state.js";

/** @typedef {import('./types.js').Alert} Alert */

/** Some proxies accept the upgrade and then never complete it. */
const HANDSHAKE_TIMEOUT_MS = 5000;

/**
 * @param {unknown} value
 * @returns {value is Alert}
 */
function isAlert(value) {
  return typeof value === "object" && value !== null && "id" in value && "email_id" in value;
}

/**
 * Connect, and deliver each alert to `onAlert`.  Returns a function that
 * disconnects; call it and connect again when the PII-mask preference
 * changes, since the feed is masked at connection time.
 * @param {(alert: Alert) => void} onAlert
 * @returns {() => void}
 */
export function startLiveFeed(onAlert) {
  const mask = preferences.mask;
  let stopped = false;
  /** @type {EventSource | null} */
  let source = null;
  /** @type {WebSocket | null} */
  let socket = null;

  /** @param {string} text */
  const deliver = (text) => {
    try {
      const data = JSON.parse(text);
      if (isAlert(data)) onAlert(data);
    } catch {
      // Not an alert frame; ignore it.
    }
  };

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
