// @ts-check

/** @type {ReactNS.Static} */
const React = /** @type {any} */ (globalThis).React;
/**
 * htm reads its element factory from `this`, so `htm.bind(h)` is its documented
 * way of producing a tag function - not partial application.
 * @type {{ bind(h: (type: unknown, props: Record<string, unknown> | null, ...children: unknown[]) => ReactNS.Element): HtmlTag }}
 */
const htm = /** @type {any} */ (globalThis).htm;

if (!React || !htm) {
  throw new Error("React and htm must load before js/react.js (see the script tags in index.html)");
}

/** @typedef {(strings: TemplateStringsArray, ...values: unknown[]) => ReactNS.Element} HtmlTag */

/** HTML attribute name -> the React prop that means the same thing. */
const RENAMED = /** @type {Record<string, string>} */ ({ class: "className", for: "htmlFor" });

/**
 * `"--value:40;background:red"` -> `{ "--value": "40", background: "red" }`.
 * React has accepted custom properties in a style object since 16.
 * @param {string} css
 * @returns {Record<string, string>}
 */
function parseStyle(css) {
  /** @type {Record<string, string>} */
  const style = {};
  for (const declaration of css.split(";")) {
    const colon = declaration.indexOf(":");
    if (colon < 0) continue;
    const name = declaration.slice(0, colon).trim();
    if (name) style[name] = declaration.slice(colon + 1).trim();
  }
  return style;
}

/**
 * @param {unknown} type
 * @param {Record<string, unknown> | null} props
 * @param {...unknown} children
 */
function h(type, props, ...children) {
  /** @type {Record<string, unknown> | null} */
  let mapped = null;
  if (props) {
    mapped = {};
    for (const [key, value] of Object.entries(props)) {
      if (key === "style" && typeof value === "string") mapped.style = parseStyle(value);
      else mapped[RENAMED[key] ?? key] = value;
    }
  }
  return React.createElement(type, mapped, ...children);
}

/**
 * Tagged-template markup: ``html`<b class="x">${name}</b>` ``.
 * @type {HtmlTag}
 */
export const html = htm.bind(h);

export const {
  Fragment,
  createElement,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} = React;

export { React };
