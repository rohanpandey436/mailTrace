// @ts-check
/**
 * The relationship graph (Cytoscape.js): nodes coloured by type, sized by risk.
 *
 * In a campaign view the nodes sitting between two emails are the shared pieces
 * of the attacker's setup, which is what an investigator follows.
 *
 * Cytoscape owns its container's DOM, so React owns only the container and the
 * tooltip: the instance is built in an effect and destroyed on unmount, and
 * hover state is lifted into React so the tooltip is a component rather than
 * innerHTML written from an event handler.
 */
import { NODE_TYPE } from "../labels.js";
import { Fragment, html, useEffect, useRef, useState } from "../react.js";
import { color, toneColor } from "../theme.js";

/** @typedef {import('../types.js').AttributionGraph} AttributionGraph */
/** @typedef {import('../types.js').NodeType} NodeType */
/** @typedef {{ label: string, kind: string, risk: string, x: number, y: number }} Hovered */

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
    { selector: "edge", style: { width: 1.3, "line-color": color("line-strong"), "curve-style": "bezier" } },
  ];
}

/**
 * @param {{ graph: AttributionGraph, tall?: boolean }} props
 */
export function RelationshipGraph({ graph, tall = false }) {
  const container = useRef(/** @type {HTMLDivElement | null} */ (null));
  const [hovered, setHovered] = useState(/** @type {Hovered | null} */ (null));

  useEffect(() => {
    const element = container.current;
    if (!element || graph.nodes.length === 0 || typeof cytoscape === "undefined") return undefined;

    const ids = new Set(graph.nodes.map((node) => node.id));
    const cy = cytoscape({
      container: element,
      elements: [
        ...graph.nodes.map((node) => ({ data: { id: node.id, label: node.label, type: node.type, risk: node.risk } })),
        ...graph.edges
          .filter((edge) => ids.has(edge.source) && ids.has(edge.target))
          .map((edge, index) => ({
            data: { id: `edge-${index}`, source: edge.source, target: edge.target, relation: edge.relation },
          })),
      ],
      style: stylesheet(),
      layout: { name: "cose", animate: false, padding: LAYOUT_PADDING },
      minZoom: ZOOM_RANGE.min,
      maxZoom: ZOOM_RANGE.max,
      wheelSensitivity: WHEEL_SENSITIVITY,
      boxSelectionEnabled: false,
    });

    /** @param {cytoscape.EventObject} event */
    const show = (event) => {
      const data = event.target.data();
      setHovered({
        label: data.label,
        kind: nodeType(data.type).label,
        risk: data.risk,
        x: event.originalEvent.clientX,
        y: event.originalEvent.clientY,
      });
    };
    cy.on("mouseover", "node", show);
    cy.on("mousemove", "node", show);
    cy.on("mouseout", "node", () => setHovered(null));

    return () => {
      setHovered(null);
      cy.destroy();
    };
  }, [graph]);

  if (graph.nodes.length === 0) {
    return html`<div class="card card--tight hint">Nothing to draw for this email.</div>`;
  }
  return html`<${Fragment}>
    <div class=${`graph${tall ? " graph--tall" : ""}`} ref=${container}></div>
    ${hovered &&
    html`<div class="tooltip" style=${{ left: `${hovered.x + TOOLTIP_OFFSET_PX}px`, top: `${hovered.y + TOOLTIP_OFFSET_PX}px` }}>
      <b>${hovered.label}</b>
      <div class="muted">${hovered.kind} · danger: ${hovered.risk}</div>
    </div>`}
  </>`;
}

/** The colour key shown under a graph. */
export function GraphLegend() {
  return html`<div class="hint legend">
    ${Object.entries(NODE_TYPE).map(
      ([key, type]) => html`<span key=${key} class="legend__item"><span class=${`dot tone-${type.tone}`}></span>${type.label}</span>`,
    )}
    <span class="legend__hint">Bigger circle = more dangerous. Drag anything to move it.</span>
  </div>`;
}
