import { useCallback, useEffect, useState } from "./react.js";

export function useAsync(load, deps) {
  const [data, setData] = useState((null));
  const [error, setError] = useState((null));
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    load()
      .then((result) => {
        if (cancelled) return;
        setData(result);
        setLoading(false);
      })
      .catch((cause) => {
        if (cancelled) return;
        setError(cause instanceof Error ? cause.message : String(cause));
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [...deps, attempt]);

  return { data, error, loading, reload };
}

export function useStore(store) {
  const [value, setValue] = useState(store.get);
  useEffect(() => store.subscribe(() => setValue(store.get())), [store]);
  return value;
}
