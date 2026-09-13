import { urls } from "./api.js";
import { preferences } from "./state.js";

const HANDSHAKE_TIMEOUT_MS = 5000;

const listeners = new Set();
let disconnect = null;
let connectedMask = false;

function isAlert(value) {
  return typeof value === "object" && value !== null && "id" in value && "email_id" in value;
}

function deliver(text) {
  try {
    const data = JSON.parse(text);
    if (isAlert(data)) for (const listener of listeners) listener(data);
  } catch {
  }
}

function connect() {
  const mask = preferences.mask;
  connectedMask = mask;
  let stopped = false;
  let source = null;
  let socket = null;

  const startSse = () => {
    if (stopped || source || !("EventSource" in window)) return;
    source = new EventSource(urls.alertStream(mask));
    source.addEventListener("alert", (event) => deliver((event).data));
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
  ws.onclose = () => startSse();
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

export function resyncMask() {
  if (!disconnect || connectedMask === preferences.mask) return;
  disconnect();
  disconnect = listeners.size > 0 ? connect() : null;
}
