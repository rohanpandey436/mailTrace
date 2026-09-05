// @ts-check
/**
 * DOM helpers and the `html` template tag.
 *
 * All markup goes through `html`, which escapes every interpolated value, so
 * escaping is the default and forgetting it is impossible. The only way in
 * unescaped is a `SafeHtml` from another `html` call or from `raw()`.
 */

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/**
 * @param {unknown} value
 * @returns {string}
 */
export function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"']/g, (char) => ESCAPES[/** @type {keyof ESCAPES} */ (char)]);
}

/** Markup that has already been escaped or is trusted by construction. */
export class SafeHtml {
  /** @param {string} value */
  constructor(value) {
    this.value = value;
  }

  toString() {
    return this.value;
  }
}

/** @typedef {SafeHtml | string | number | boolean | null | undefined | RenderableList} Renderable */
/** @typedef {Renderable[]} RenderableList */

/**
 * Mark a string as markup.  Use only for content that is escaped already.
 * @param {string} markup
 */
export function raw(markup) {
  return new SafeHtml(markup);
}

/**
 * @param {Renderable} value
 * @returns {string}
 */
function render(value) {
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  if (value === null || value === undefined || value === false) return "";
  return esc(value);
}

/**
 * Template tag: `html\`<b>${name}</b>\`` escapes `name`.  Arrays are joined,
 * `false`/`null`/`undefined` render as nothing so `${cond && html\`...\`}` works.
 * @param {TemplateStringsArray} strings
 * @param {...Renderable} values
 * @returns {SafeHtml}
 */
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((value, index) => {
    out += render(value) + strings[index + 1];
  });
  return new SafeHtml(out);
}

/**
 * Render an attribute: `attr("title", text)` gives ` title="..."`, a `true`
 * gives a bare attribute, and `false`/empty gives nothing.
 * @param {string} name
 * @param {string | number | boolean | null | undefined} value
 */
export function attr(name, value) {
  if (value === true) return new SafeHtml(` ${name}`);
  if (value === false || value === null || value === undefined || value === "") return new SafeHtml("");
  return new SafeHtml(` ${name}="${esc(value)}"`);
}

/**
 * @param {Element} element
 * @param {Renderable} content
 */
export function mount(element, content) {
  element.innerHTML = render(content);
}

/**
 * @param {string} selector
 * @param {ParentNode} [root]
 * @returns {HTMLElement | null}
 */
export function $(selector, root = document) {
  return /** @type {HTMLElement | null} */ (root.querySelector(selector));
}

/**
 * @param {string} selector
 * @param {ParentNode} [root]
 * @returns {HTMLElement[]}
 */
export function $$(selector, root = document) {
  return /** @type {HTMLElement[]} */ (Array.from(root.querySelectorAll(selector)));
}

/**
 * Like `$`, for elements the markup guarantees exist.  Throws instead of
 * returning null so a typo in a selector fails loudly, not silently.
 * @param {string} selector
 * @param {ParentNode} [root]
 * @returns {HTMLElement}
 */
export function must(selector, root = document) {
  const element = $(selector, root);
  if (!element) throw new Error(`missing element: ${selector}`);
  return element;
}

/**
 * Delegated event listener: `handler` runs when the event's target, or one of
 * its ancestors inside `root`, matches `selector`.
 * @param {Element | Document} root
 * @param {string} type
 * @param {string} selector
 * @param {(event: Event, target: HTMLElement) => void} handler
 */
export function on(root, type, selector, handler) {
  root.addEventListener(type, (event) => {
    if (!(event.target instanceof Element)) return;
    const target = /** @type {HTMLElement | null} */ (event.target.closest(selector));
    if (target && root.contains(target)) handler(event, target);
  });
}

/**
 * Space and Enter activate an element that is not a native button.
 * @param {HTMLElement} element
 * @param {() => void} action
 */
export function activatable(element, action) {
  element.addEventListener("click", action);
  element.addEventListener("keydown", (event) => {
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      action();
    }
  });
}
