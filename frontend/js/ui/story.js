import { prefersReducedMotion, useStore } from "../hooks.js";
import { html, useEffect, useRef, useState } from "../react.js";
import { pageSections } from "../state.js";

const SECTION_PREFIX = "section-";
const SPY_SLACK_PX = 48;
const NEAR_VIEWPORT = "500px 0px";
const REVEAL_EVENT = "mailtrace:reveal";
const STRIP_EDGE_PX = 8;
const SETTLE_TOLERANCE_PX = 6;
const SETTLE_AFTER_MS = [900, 1800];
const USER_SCROLL_EVENTS = ["wheel", "touchstart", "keydown"];
const NONE = { items: [], active: "" };

let jumps = 0;

function offTarget(target) {
  const wanted = parseFloat(getComputedStyle(target).scrollMarginTop) || 0;
  return Math.abs(target.getBoundingClientRect().top - wanted) > SETTLE_TOLERANCE_PX;
}

export function jumpTo(id) {
  window.dispatchEvent(new Event(REVEAL_EVENT));
  jumps += 1;
  const mine = jumps;
  const stop = () => {
    jumps += 1;
  };
  for (const name of USER_SCROLL_EVENTS) window.addEventListener(name, stop, { once: true, passive: true });
  const settle = () => {
    const target = document.getElementById(SECTION_PREFIX + id);
    if (mine === jumps && target && offTarget(target)) target.scrollIntoView({ behavior: "auto", block: "start" });
  };
  const go = () => {
    const target = document.getElementById(SECTION_PREFIX + id);
    if (!target) return;
    target.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
    target.focus({ preventScroll: true });
    for (const wait of SETTLE_AFTER_MS) window.setTimeout(settle, wait);
  };
  requestAnimationFrame(() => requestAnimationFrame(go));
}

export function useSections(items) {
  useEffect(() => {
    const first = items.length > 0 ? items[0].id : "";
    const last = items.length > 0 ? items[items.length - 1].id : "";
    pageSections.set({ items, active: first });
    let frame = 0;
    const measure = () => {
      frame = 0;
      let current = first;
      let line = 0;
      for (const item of items) {
        const element = document.getElementById(SECTION_PREFIX + item.id);
        if (!element) continue;
        line = line || (parseFloat(getComputedStyle(element).scrollMarginTop) || 0) + SPY_SLACK_PX;
        if (element.getBoundingClientRect().top <= line) current = item.id;
      }
      const page = document.documentElement;
      if (window.scrollY > 0 && window.innerHeight + window.scrollY >= page.scrollHeight - 2) current = last;
      pageSections.set((state) => (state.active === current ? state : { ...state, active: current }));
    };
    const schedule = () => {
      if (!frame) frame = requestAnimationFrame(measure);
    };
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    measure();
    return () => {
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
      cancelAnimationFrame(frame);
      pageSections.set(NONE);
    };
  }, [items]);
}

export function StorySection({ id, title = "", intro = "", children }) {
  return html`<section class="story" id=${SECTION_PREFIX + id} tabIndex=${-1} aria-label=${title ? undefined : "Verdict"} aria-labelledby=${title ? `story-${id}` : undefined}>
    ${title && html`<h2 class="story__title" id=${`story-${id}`}>${title}</h2>`}
    ${intro && html`<p class="story__intro">${intro}</p>`}
    ${children}
  </section>`;
}

export function LazyMount({ height = "12rem", children }) {
  const holder = useRef((null));
  const [shown, setShown] = useState(false);

  useEffect(() => {
    if (shown) return undefined;
    const show = () => setShown(true);
    const element = holder.current;
    if (!element || !("IntersectionObserver" in window)) {
      show();
      return undefined;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) show();
      },
      { rootMargin: NEAR_VIEWPORT },
    );
    observer.observe(element);
    window.addEventListener(REVEAL_EVENT, show);
    return () => {
      observer.disconnect();
      window.removeEventListener(REVEAL_EVENT, show);
    };
  }, [shown]);

  if (shown) return children;
  return html`<div class="skeleton story__placeholder" ref=${holder} style=${{ "--height": height }}></div>`;
}

export function SectionMenu() {
  const { items, active } = useStore(pageSections);
  if (items.length === 0) return null;
  return html`<div class="rail__sections" role="group" aria-label="On this page">
    <div class="rail__sections-title" aria-hidden="true">On this page</div>
    ${items.map(
      (item) => html`<button
        key=${item.id}
        type="button"
        class=${`rail__section${active === item.id ? " is-active" : ""}`}
        aria-current=${active === item.id ? "location" : undefined}
        onClick=${() => jumpTo(item.id)}
      >
        ${item.label}
      </button>`,
    )}
  </div>`;
}

export function JumpBar() {
  const { items, active } = useStore(pageSections);
  const strip = useRef((null));
  const [more, setMore] = useState("");

  useEffect(() => {
    const element = strip.current;
    if (!element) return undefined;
    const measure = () => {
      const before = element.scrollLeft > 1;
      const after = element.scrollLeft + element.clientWidth < element.scrollWidth - 1;
      setMore(before && after ? "both" : before ? "start" : after ? "end" : "");
    };
    measure();
    element.addEventListener("scroll", measure, { passive: true });
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => {
      element.removeEventListener("scroll", measure);
      observer.disconnect();
    };
  }, [items.length]);

  useEffect(() => {
    const element = strip.current;
    const chosen = element?.querySelector('[aria-current="location"]');
    if (!element || !(chosen instanceof HTMLElement)) return;
    const start = chosen.offsetLeft;
    const end = start + chosen.offsetWidth;
    if (start < element.scrollLeft) element.scrollLeft = start - STRIP_EDGE_PX;
    else if (end > element.scrollLeft + element.clientWidth) element.scrollLeft = end - element.clientWidth + STRIP_EDGE_PX;
  }, [active]);

  if (items.length === 0) return null;
  return html`<nav class="jumpbar" aria-label="On this page">
    <div class=${`tabs${more ? ` tabs--more-${more}` : ""}`} ref=${strip}>
      ${items.map(
        (item) => html`<button
          key=${item.id}
          type="button"
          class=${`tab${active === item.id ? " is-active" : ""}`}
          aria-current=${active === item.id ? "location" : undefined}
          onClick=${() => jumpTo(item.id)}
        >
          ${item.label}
        </button>`,
      )}
    </div>
  </nav>`;
}
