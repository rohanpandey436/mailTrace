const CDN = "https://cdnjs.cloudflare.com/ajax/libs";
const LEAFLET = `${CDN}/leaflet/1.9.4`;
const CYTOSCAPE = `${CDN}/cytoscape/3.30.4/cytoscape.min.js`;
const IDLE_TIMEOUT_MS = 3000;
const IDLE_FALLBACK_MS = 1200;

const pending = new Map();

function once(key, start) {
  let promise = pending.get(key);
  if (!promise) {
    promise = start().catch((error) => {
      pending.delete(key);
      throw error;
    });
    pending.set(key, promise);
  }
  return promise;
}

function attach(element, address, place) {
  return new Promise((resolve, reject) => {
    element.onload = () => resolve(undefined);
    element.onerror = () => {
      element.remove();
      reject(new Error(`could not load ${address}`));
    };
    place(element);
  });
}

function script(src) {
  return once(src, () => {
    const element = document.createElement("script");
    element.src = src;
    element.async = true;
    return attach(element, src, (node) => document.head.append(node));
  });
}

function stylesheet(href) {
  return once(href, () => {
    const element = document.createElement("link");
    element.rel = "stylesheet";
    element.href = href;
    const own = document.querySelector('link[rel="stylesheet"][href^="css/app.css"]');
    return attach(element, href, (node) => document.head.insertBefore(node, own));
  });
}

export function loadLeaflet() {
  return Promise.all([stylesheet(`${LEAFLET}/leaflet.min.css`), script(`${LEAFLET}/leaflet.min.js`)]);
}

export function loadCytoscape() {
  return script(CYTOSCAPE);
}

export function warmUp(load) {
  const run = () => {
    load().catch(() => {});
  };
  if ("requestIdleCallback" in window) window.requestIdleCallback(run, { timeout: IDLE_TIMEOUT_MS });
  else window.setTimeout(run, IDLE_FALLBACK_MS);
}
