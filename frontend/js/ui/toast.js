import { html, useEffect, useState } from "../react.js";
import { icon } from "./icons.js";

const LIFETIME_MS = { success: 5200, error: 9000, alert: 9000 };
const RESUME_MS = 2500;
const FADE_MS = 300;
const MAX_SHOWN = 4;
const ICON = { success: "check", error: "alert", alert: "bell" };

let queue = [];
const listeners = new Set();
const timers = new Map();
let nextId = 1;

function publish() {
  for (const listener of listeners) listener(queue);
}

function hold(id) {
  window.clearTimeout(timers.get(id));
  timers.delete(id);
}

function dismiss(id) {
  hold(id);
  if (!queue.some((item) => item.id === id && !item.leaving)) return;
  queue = queue.map((item) => (item.id === id ? { ...item, leaving: true } : item));
  publish();
  window.setTimeout(() => {
    queue = queue.filter((item) => item.id !== id);
    publish();
  }, FADE_MS);
}

function arm(id, wait) {
  hold(id);
  timers.set(
    id,
    window.setTimeout(() => dismiss(id), wait),
  );
}

export function toast(content, kind = "success") {
  const id = nextId++;
  queue = [...queue, { id, kind, content, leaving: false }];
  publish();
  arm(id, LIFETIME_MS[kind]);
  const shown = queue.filter((item) => !item.leaving);
  for (const extra of shown.slice(0, Math.max(0, shown.length - MAX_SHOWN))) dismiss(extra.id);
  return id;
}

export function Toasts() {
  const [toasts, setToasts] = useState(queue);
  useEffect(() => {
    listeners.add(setToasts);
    return () => {
      listeners.delete(setToasts);
    };
  }, []);
  return html`<div class="toasts" role="status" aria-live="polite">
    ${toasts.map(
      (item) =>
        html`<div
          key=${item.id}
          class=${`toast toast--${item.kind}${item.leaving ? " is-leaving" : ""}`}
          role=${item.kind === "error" ? "alert" : undefined}
          onMouseEnter=${() => hold(item.id)}
          onMouseLeave=${() => arm(item.id, RESUME_MS)}
          onFocus=${() => hold(item.id)}
          onBlur=${() => arm(item.id, RESUME_MS)}
        >
          ${icon(ICON[item.kind], "toast__icon")}
          <div class="toast__body">${item.content}</div>
          <button class="toast__close" type="button" aria-label="Dismiss this message" onClick=${() => dismiss(item.id)}>
            ${icon("close")}
          </button>
        </div>`,
    )}
  </div>`;
}
