import { useVendor } from "../hooks.js";
import { NODE_TYPE } from "../labels.js";
import { loadCytoscape } from "../libs.js";
import { Fragment, html, useEffect, useRef, useState } from "../react.js";
import { color, toneColor } from "../theme.js";

const DIAMETER = { info: 14, low: 16, medium: 20, high: 24, critical: 28 };
const DEFAULT_DIAMETER = DIAMETER.info;
const LABEL_FONT_PX = 11;
const LABEL_MAX_WIDTH_PX = 130;
const LABEL_HIDDEN_BELOW_PX = 6;
const TOOLTIP_OFFSET_PX = 14;
const ZOOM_RANGE = { min: 0.3, max: 4 };
const OPENING_ZOOM_MAX = 1.5;
const WHEEL_SENSITIVITY = 0.2;
const LAYOUT_PADDING = 30;
const RING = { campaign: 3, email: 2 };
const OUTER_RING = 1;
const CROWDED_EMAILS = 12;
const SPACING = { roomy: 12, crowded: 20 };

function ring(node) {
  const type = node.data("type");
  return type in RING ? RING[(type)] : OUTER_RING;
}

function layout(crowded) {
  return {
    name: "concentric",
    animate: false,
    padding: LAYOUT_PADDING,
    nodeDimensionsIncludeLabels: !crowded,
    minNodeSpacing: crowded ? SPACING.crowded : SPACING.roomy,
    startAngle: (3 * Math.PI) / 2,
    levelWidth: () => 1,
    concentric: ring,
  };
}

function nodeType(type) {
  return type in NODE_TYPE ? NODE_TYPE[(type)] : { label: type, tone: ("neutral") };
}

function diameter(risk) {
  return risk in DIAMETER ? DIAMETER[(risk)] : DEFAULT_DIAMETER;
}

function stylesheet(crowded) {
  return [
    {
      selector: "node",
      style: {
        "background-color": (node) => toneColor(nodeType(node.data().type).tone),
        width: (node) => diameter(node.data().risk),
        height: (node) => diameter(node.data().risk),
        "border-width": 2,
        "border-color": color("card"),
        label: (node) => (crowded && node.data("type") === "email" ? "" : node.data("label")),
        "font-size": LABEL_FONT_PX,
        color: color("ink-soft"),
        "text-valign": "bottom",
        "text-halign": "center",
        "text-margin-y": 4,
        "text-wrap": "ellipsis",
        "text-max-width": LABEL_MAX_WIDTH_PX,
        "text-background-color": color("paper"),
        "text-background-opacity": 0.85,
        "text-background-padding": 2,
        "text-background-shape": "roundrectangle",
        "min-zoomed-font-size": LABEL_HIDDEN_BELOW_PX,
      },
    },
    { selector: "edge", style: { width: 1.3, "line-color": color("line-strong"), "curve-style": "bezier" } },
  ];
}

export function RelationshipGraph({ graph, tall = false }) {
  const container = useRef((null));
  const [hovered, setHovered] = useState((null));
  const library = useVendor(loadCytoscape);

  useEffect(() => {
    const element = container.current;
    if (!element || graph.nodes.length === 0 || library !== "ready" || typeof cytoscape === "undefined") return undefined;

    const ids = new Set(graph.nodes.map((node) => node.id));
    const crowded = graph.nodes.filter((node) => node.type === "email").length > CROWDED_EMAILS;
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
      style: stylesheet(crowded),
      layout: layout(crowded),
      minZoom: ZOOM_RANGE.min,
      maxZoom: ZOOM_RANGE.max,
      wheelSensitivity: WHEEL_SENSITIVITY,
      boxSelectionEnabled: false,
    });
    if (cy.zoom() > OPENING_ZOOM_MAX) {
      cy.zoom(OPENING_ZOOM_MAX);
      cy.center();
    }

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
  }, [graph, library]);

  if (graph.nodes.length === 0) {
    return html`<div class="card card--tight hint">Nothing to draw for this email.</div>`;
  }
  if (library === "failed") {
    return html`<div class="card card--tight hint">The map could not be loaded. Check your internet connection and open this page again.</div>`;
  }
  return html`<${Fragment}>
    <div class=${`graph${tall ? " graph--tall" : ""}${library === "loading" ? " is-loading" : ""}`} ref=${container}></div>
    ${hovered &&
    html`<div class="tooltip" style=${{ left: `${hovered.x + TOOLTIP_OFFSET_PX}px`, top: `${hovered.y + TOOLTIP_OFFSET_PX}px` }}>
      <b>${hovered.label}</b>
      <div class="muted">${hovered.kind} · danger: ${hovered.risk}</div>
    </div>`}
  </>`;
}

export function GraphLegend() {
  return html`<div class="hint legend">
    ${Object.entries(NODE_TYPE).map(
      ([key, type]) => html`<span key=${key} class="legend__item"><span class=${`dot tone-${type.tone}`}></span>${type.label}</span>`,
    )}
    <span class="legend__hint">Bigger circle = more dangerous. Drag anything to move it.</span>
  </div>`;
}
