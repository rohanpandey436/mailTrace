// @ts-check
/**
 * Hash router.
 *
 * A view is an async function that fills a container and may return a
 * cleanup function (the map and the graph hold resources that must be
 * released).  The router runs the previous view's cleanup before rendering
 * the next, and turns a thrown error into an error state with a retry.
 */
import { $, mount } from "./dom.js";
import { errorState } from "./ui/primitives.js";

/** @typedef {() => void} Cleanup */
/** @typedef {(container: HTMLElement, param: string) => Promise<Cleanup | void>} View */
/** @typedef {{ name: string, param: string }} Route */

/** @type {Map<string, View>} */
const views = new Map();
/** @type {Cleanup | null} */
let cleanup = null;
/** @type {HTMLElement | null} */
let outlet = null;
/** @type {((route: Route) => void) | null} */
let onChange = null;
const DEFAULT_VIEW = "dashboard";

/**
 * @param {string} name
 * @param {View} view
 */
export function defineView(name, view) {
  views.set(name, view);
}

/** @returns {Route} */
export function currentRoute() {
  const [name = DEFAULT_VIEW, param = ""] = location.hash.replace(/^#\/?/, "").split("/");
  return { name, param };
}

/**
 * @param {string} hash e.g. `#/email/abc`
 */
export function navigate(hash) {
  if (location.hash === hash) {
    void refresh();
  } else {
    location.hash = hash;
  }
}

/** Re-render the current route (after a preference changed, say). */
export async function refresh() {
  if (!outlet) return;
  const route = currentRoute();
  const view = views.get(route.name) ?? views.get(DEFAULT_VIEW);
  if (!view) return;
  if (cleanup) {
    cleanup();
    cleanup = null;
  }
  onChange?.(route);
  // Each render gets its own root.  A view that is still awaiting data when
  // the route changes then writes into a detached element instead of over
  // the view that replaced it.
  const container = document.createElement("div");
  outlet.replaceChildren(container);
  try {
    cleanup = (await view(container, route.param)) ?? null;
  } catch (error) {
    mount(container, errorState(error instanceof Error ? error.message : String(error)));
    $("[data-retry]", container)?.addEventListener("click", () => void refresh());
  }
}

/**
 * @param {HTMLElement} container
 * @param {(route: Route) => void} [listener] called before each render
 */
export function startRouter(container, listener) {
  outlet = container;
  onChange = listener ?? null;
  window.addEventListener("hashchange", () => void refresh());
  void refresh();
}
