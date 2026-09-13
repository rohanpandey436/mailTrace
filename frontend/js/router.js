import { useEffect, useState } from "./react.js";

const DEFAULT_VIEW = "dashboard";

export function currentRoute() {
  const [name = DEFAULT_VIEW, param = ""] = location.hash.replace(/^#\/?/, "").split("/");
  return { name, param: decodeURIComponent(param) };
}

export function navigate(hash) {
  if (location.hash === hash) window.dispatchEvent(new HashChangeEvent("hashchange"));
  else location.hash = hash;
}

export function useRoute() {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const update = () => setRoute(currentRoute());
    window.addEventListener("hashchange", update);
    return () => window.removeEventListener("hashchange", update);
  }, []);
  return route;
}
