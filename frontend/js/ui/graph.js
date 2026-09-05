// @ts-check
/**
 * The relationship graph (Cytoscape.js).
 *
 * Nodes are the things an email touches - addresses, domains, IPs, links,
 * attachments - coloured by type and sized by risk.  In a campaign view the
 * nodes sitting between two emails are the shared pieces of the attacker's
 * setup, which is exactly what an investigator follows.
 */
import { esc, html, mount, must } from "../dom.js";
import { NODE_TYPE } from "../labels.js";
import { color, toneColor } from "../theme.js";

/** @typedef {import('../types.js').AttributionGraph} AttributionGraph */
/** @typedef {import('../types.js').NodeType} NodeType */

/** Node diameter in pixels by risk: bigger circle, more dangerous. */
const DIAMETER = { info: 14, low: 16, medium: 20, high: 24, critical: 28 };
const DEFAULT_DIAMETER = DIAMETER.info;
const LABEL_FONT_PX = 9;
const LABEL_MAX_WIDTH_PX = 110;
const TOOLTIP_OFFSET_PX = 14;
const ZOOM_RANGE = { min: 0.3, max: 4 };
const WHEEL_SENSITIVITY = 0.2;
const LAYOUT_PADDING = 30;

/**
 * @param {string} type
 */
function nodeType(type) {
  return type in NODE_TYPE ? NODE_TYPE[/** @type {NodeType} */ (type)] : { label: type, tone: /** @type {const} */ ("neutral") };
}

/**
 * @param {string} risk
 */
function diameter(risk) {
  return risk in DIAMETER ? DIAMETER[/** @type {keyof DIAMETER} */ (risk)] : DEFAULT_DIAMETER;
}

/** @returns {cytoscape.StyleRule[]} */
function stylesheet() {
  return [
    {
      selector: "node",
      style: {
        "background-color": (node) => toneColor(nodeType(node.data().type).tone),
        width: (node) => diameter(node.data().risk),
        height: (node) => diameter(node.data().risk),
        "border-width": 2,
        "border-color": color("card"),
        label: "data(label)",
        "font-size": LABEL_FONT_PX,
        color: color("ink-soft"),
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 4,
        "text-wrap": "ellipsis",
        "text-max-width": LABEL_MAX_WIDTH_PX,
      },
    },
    {
      selector: "edge",
      style: { width: 1.3, "line-color": color("line-strong"), "curve-style": "bezier" },
    },
  ];
}

/**
 * Draw `graph` into `container`.  Returns the function that tears it down.
 * @param {HTMLElement} container
 * @param {AttributionGraph} graph
 * @returns {() => void}
 */
export function createGraph(container, graph) {
  if (graph.nodes.length === 0) {
    mount(container, html`<div class="hint card--tight">Nothing to draw for this email.</div>`);
    return () => {};
  }
  const ids = new Set(graph.nodes.map((node) => node.id));
  const elements = [
    ...graph.nodes.map((node) => ({ data: { id: node.id, label: node.label, type: node.type, risk: node.risk } })),
    ...graph.edges
      .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
      .map((edge, index) => ({ data: { id: `edge-${index}`, source: edge.source, target: edge.target, relation: edge.relation } })),
  ];
  const cy = cytoscape({
    container,
    elements,
    style: stylesheet(),
    layout: { name: "cose", animate: false, padding: LAYOUT_PADDING },
    minZoom: ZOOM_RANGE.min,
    maxZoom: ZOOM_RANGE.max,
    wheelSensitivity: WHEEL_SENSITIVITY,
    boxSelectionEnabled: false,
  });

  const tooltip = must("#tooltip");
  /** @param {MouseEvent} event */
  const follow = (event) => {
    tooltip.style.left = `${event.clientX + TOOLTIP_OFFSET_PX}px`;
    tooltip.style.top = `${event.clientY + TOOLTIP_OFFSET_PX}px`;
  };
  cy.on("mouseover", "node", (event) => {
    const data = event.target.data();
    tooltip.innerHTML = `<b>${esc(data.label)}</b><div class="muted">${esc(nodeType(data.type).label)} · danger: ${esc(data.risk)}</div>`;
    tooltip.hidden = false;
    follow(event.originalEvent);
  });
  cy.on("mousemove", "node", (event) => follow(event.originalEvent));
  cy.on("mouseout", "node", () => {
    tooltip.hidden = true;
  });

  return () => {
    tooltip.hidden = true;
    cy.destroy();
  };
}

/** The colour key shown under a graph. */
export function graphLegend() {
  return html`<div class="hint legend">
    ${Object.values(NODE_TYPE).map((type) => html`<span class="legend__item"><span class="dot tone-${type.tone}"></span>${type.label}</span>`)}
    <span class="legend__hint">Bigger circle = more dangerous. Drag anything to move it.</span>
  </div>`;
}
