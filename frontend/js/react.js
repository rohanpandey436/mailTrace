const React = (globalThis).React;
const htm = (globalThis).htm;

if (!React || !htm) {
  throw new Error("React and htm must load before js/react.js (see the script tags in index.html)");
}

const RENAMED = ({ class: "className", for: "htmlFor" });

function parseStyle(css) {
  const style = {};
  for (const declaration of css.split(";")) {
    const colon = declaration.indexOf(":");
    if (colon < 0) continue;
    const name = declaration.slice(0, colon).trim();
    if (name) style[name] = declaration.slice(colon + 1).trim();
  }
  return style;
}

function h(type, props, ...children) {
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
