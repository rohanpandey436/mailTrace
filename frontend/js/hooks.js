import { friendlyError } from "./api.js";
import { useCallback, useEffect, useState } from "./react.js";

const SLOW_AFTER_MS = 4000;

export function useAsync(load, deps) {
  const [data, setData] = useState((null));
  const [error, setError] = useState((null));
  const [loading, setLoading] = useState(true);
  const [slow, setSlow] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setSlow(false);
    const timer = window.setTimeout(() => {
      if (!cancelled) setSlow(true);
    }, SLOW_AFTER_MS);
    load()
      .then((result) => {
        if (cancelled) return;
        setData(result);
        setLoading(false);
      })
      .catch((cause) => {
        if (cancelled) return;
        setError(friendlyError(cause));
        setLoading(false);
      });
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [...deps, attempt]);

  return { data, error, loading, slow, reload };
}

export function useOnline() {
  const [online, setOnline] = useState(typeof navigator === "undefined" ? true : navigator.onLine);
  useEffect(() => {
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener("online", up);
    window.addEventListener("offline", down);
    return () => {
      window.removeEventListener("online", up);
      window.removeEventListener("offline", down);
    };
  }, []);
  return online;
}

export function useStore(store) {
  const [value, setValue] = useState(store.get);
  useEffect(() => store.subscribe(() => setValue(store.get())), [store]);
  return value;
}
