// @ts-check
import { useEffect, useState } from "./react.js";

/** @typedef {{ name: string, param: string }} Route */

const DEFAULT_VIEW = "dashboard";

/** @returns {Route} */
export function currentRoute() {
  const [name = DEFAULT_VIEW, param = ""] = location.hash.replace(/^#\/?/, "").split("/");
  return { name, param: decodeURIComponent(param) };
}

/**
 * Go to `hash`. Assigning the same hash fires no `hashchange`, so a repeat
 * navigation (searching again from the case list, say) is nudged by hand.
 * @param {string} hash
 */
export function navigate(hash) {
  if (location.hash === hash) window.dispatchEvent(new HashChangeEvent("hashchange"));
  else location.hash = hash;
}

/** The current route, re-rendering the caller whenever it changes. */
export function useRoute() {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const update = () => setRoute(currentRoute());
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return route;
}
