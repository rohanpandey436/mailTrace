import { friendlyError } from "./api.js";
import { useCallback, useEffect, useRef, useState } from "./react.js";

const SLOW_AFTER_MS = 4000;
const COUNT_MS = 600;

export const prefersReducedMotion = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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

export function useCountUp(target, duration = COUNT_MS) {
  const goal = Number.isFinite(target) ? Number(target) : 0;
  const [shown, setShown] = useState(() => (prefersReducedMotion() ? goal : 0));
  const current = useRef(shown);
  useEffect(() => {
    if (prefersReducedMotion() || current.current === goal) {
      current.current = goal;
      setShown(goal);
      return undefined;
    }
    const from = current.current;
    const started = performance.now();
    let frame = 0;
    const step = (now) => {
      const progress = Math.min(1, (now - started) / duration);
      const eased = 1 - (1 - progress) ** 3;
      const value = Math.round(from + (goal - from) * eased);
      current.current = value;
      setShown(value);
      if (progress < 1) frame = requestAnimationFrame(step);
    };
    frame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame);
  }, [goal, duration]);
  return shown;
}

export function useStore(store) {
  const [value, setValue] = useState(store.get);
  useEffect(() => store.subscribe(() => setValue(store.get())), [store]);
  return value;
}
