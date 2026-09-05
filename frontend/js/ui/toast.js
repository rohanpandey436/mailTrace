// @ts-check
/**
 * Transient notifications in the corner of the screen.
 */
import { html, mount, must } from "../dom.js";

/** @typedef {'success' | 'error' | 'alert'} ToastKind */

const LIFETIME_MS = { success: 5200, error: 5200, alert: 9000 };
const FADE_MS = 300;

/**
 * @param {import('../dom.js').Renderable} content
 * @param {ToastKind} [kind]
 */
export function toast(content, kind = "success") {
  const element = document.createElement("div");
  element.className = kind === "success" ? "toast" : `toast toast--${kind}`;
  mount(element, html`${content}`);
  must("#toasts").appendChild(element);
  setTimeout(() => {
    element.classList.add("is-leaving");
    setTimeout(() => element.remove(), FADE_MS);
  }, LIFETIME_MS[kind]);
}
