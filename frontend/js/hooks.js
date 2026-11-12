import { ApiError, friendlyError } from "./api.js";
import { useCallback, useEffect, useRef, useState } from "./react.js";

const SLOW_AFTER_MS = 4000;
const COUNT_MS = 600;
const SITE_NAME = "MailTrace";
const NOT_FOUND = 404;

export const prefersReducedMotion = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export function usePageTitle(title) {
  useEffect(() => {
    document.title = title ? `${title} · ${SITE_NAME}` : SITE_NAME;
  }, [title]);
}

export function useVendor(load) {
  const [state, setState] = useState("loading");
  useEffect(() => {
    let cancelled = false;
    load().then(
      () => {
        if (!cancelled) setState("ready");
      },
      () => {
        if (!cancelled) setState("failed");
      },
    );
    return () => {
      cancelled = true;
    };
  }, [load]);
  return state;
}

export function useAsync(load, deps) {
  const [data, setData] = useState((null));
  const [error, setError] = useState((null));
  const [missing, setMissing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [slow, setSlow] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setMissing(false);
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
        setMissing(cause instanceof ApiError && cause.status === NOT_FOUND);
        setLoading(false);
      });
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [...deps, attempt]);

  return { data, error, missing, loading, slow, reload };
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
