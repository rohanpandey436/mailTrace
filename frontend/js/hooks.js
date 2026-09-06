// @ts-check
import { useCallback, useEffect, useState } from "./react.js";

/**
 * @template T
 * @typedef {{ data: T | null, error: string | null, loading: boolean, reload: () => void }} AsyncState
 */

/**
 * Run `load` on mount and whenever `deps` change.
 * @template T
 * @param {() => Promise<T>} load
 * @param {readonly unknown[]} deps
 * @returns {AsyncState<T>}
 */
export function useAsync(load, deps) {
  const [data, setData] = useState(/** @type {T | null} */ (null));
  const [error, setError] = useState(/** @type {string | null} */ (null));
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

/**
 * A value that persists for the life of the page but re-renders its readers
 * when it changes. Used for the alert count, which several parts of the shell
 * display and the live feed updates.
 * @template T
 * @param {{ get: () => T, subscribe: (listener: () => void) => () => void }} store
 * @returns {T}
 */
export function useStore(store) {
  const [value, setValue] = useState(store.get);
  useEffect(() => store.subscribe(() => setValue(store.get())), [store]);
  return value;
}
