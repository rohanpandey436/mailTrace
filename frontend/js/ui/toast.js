// @ts-check
import { html, useEffect, useState } from "../react.js";

/** @typedef {'success' | 'error' | 'alert'} ToastKind */
/** @typedef {{ id: number, kind: ToastKind, content: unknown, leaving: boolean }} Toast */

const LIFETIME_MS = { success: 5200, error: 5200, alert: 9000 };
const FADE_MS = 300;

/** @type {Toast[]} */
let queue = [];
/** @type {Set<(toasts: Toast[]) => void>} */
const listeners = new Set();
let nextId = 1;

function publish() {
  for (const listener of listeners) listener(queue);
}

/**
 * @param {number} id
 * @param {Partial<Toast>} patch
 */
function update(id, patch) {
  queue = queue.map((toast) => (toast.id === id ? { ...toast, ...patch } : toast));
  publish();
}

/**
 * Show a notification. Safe to call from anywhere, component or not.
 * @param {unknown} content
 * @param {ToastKind} [kind]
 */
export function toast(content, kind = "success") {
  const id = nextId++;
  queue = [...queue, { id, kind, content, leaving: false }];
  publish();
  setTimeout(() => {
    update(id, { leaving: true });
    setTimeout(() => {
      queue = queue.filter((item) => item.id !== id);
      publish();
    }, FADE_MS);
  }, LIFETIME_MS[kind]);
  return id;
}

/** The live notification stack. Mounted once, by `<App/>`. */
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
        html`<div key=${item.id} class=${`toast${item.kind === "success" ? "" : ` toast--${item.kind}`}${item.leaving ? " is-leaving" : ""}`}>
          ${item.content}
        </div>`,
    )}
  </div>`;
}
