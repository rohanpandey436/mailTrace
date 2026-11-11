import { html, useEffect, useRef, useState } from "../react.js";
import { icon } from "./icons.js";

export function Menu({ label, ariaLabel = "", buttonClass = "btn", align = "end", caret = false, children }) {
  const [open, setOpen] = useState(false);
  const root = useRef((null));

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event) => {
      if (root.current && event.target instanceof Node && !root.current.contains(event.target)) setOpen(false);
    };
    const onKey = (event) => {
      if (event.key !== "Escape") return;
      setOpen(false);
      root.current?.querySelector("button")?.focus();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const closeOnChoice = (event) => {
    if (event.target instanceof Element && event.target.closest("a")) setOpen(false);
  };

  return html`<div class="menu" ref=${root}>
    <button
      type="button"
      class=${buttonClass}
      aria-haspopup="true"
      aria-expanded=${String(open)}
      aria-label=${ariaLabel || undefined}
      title=${ariaLabel || undefined}
      onClick=${() => setOpen(!open)}
    >
      ${label}${caret && icon("chevron", `menu__caret${open ? " is-open" : ""}`)}
    </button>
    ${open && html`<div class=${`menu__panel menu__panel--${align}`} onClick=${closeOnChoice}>${children}</div>`}
  </div>`;
}
