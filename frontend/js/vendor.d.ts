/*
 * Ambient declarations for the two libraries loaded from a CDN in index.html.
 * Only the surface the dashboard uses is declared, so the type checker can
 * hold ui/map.js and ui/graph.js to the same standard as everything else
 * without a package manager.
 */

declare namespace L {
  type LatLngTuple = [number, number];

  interface LatLng {
    lat: number;
    lng: number;
  }

  interface LatLngBounds {
    pad(ratio: number): LatLngBounds;
  }

  interface Layer {
    addTo(map: Map): this;
  }

  interface CircleMarker extends Layer {
    bindPopup(markup: string): this;
    openPopup(): this;
    on(event: "click", handler: () => void): this;
    getLatLng(): LatLng;
  }

  interface Map {
    setView(center: LatLngTuple, zoom: number): this;
    fitBounds(bounds: LatLngBounds, options?: { maxZoom?: number }): this;
    panTo(center: LatLng): this;
    invalidateSize(): this;
    remove(): void;
  }

  function map(element: HTMLElement, options?: { zoomControl?: boolean; scrollWheelZoom?: boolean }): Map;
  function tileLayer(urlTemplate: string, options?: { attribution?: string; maxZoom?: number }): Layer;
  function polyline(
    points: LatLngTuple[],
    options?: { color?: string; weight?: number; dashArray?: string; opacity?: number },
  ): Layer;
  function circleMarker(
    point: LatLngTuple,
    options?: { radius?: number; color?: string; weight?: number; fillColor?: string; fillOpacity?: number },
  ): CircleMarker;
  function latLngBounds(points: LatLngTuple[]): LatLngBounds;
}

declare namespace cytoscape {
  interface NodeData {
    id: string;
    label: string;
    type: string;
    risk: string;
  }

  interface EdgeData {
    id: string;
    source: string;
    target: string;
    relation: string;
  }

  interface NodeSingular {
    data(): NodeData;
  }

  interface EventObject {
    target: NodeSingular;
    originalEvent: MouseEvent;
  }

  type StyleValue = string | number | ((node: NodeSingular) => string | number);

  interface StyleRule {
    selector: string;
    style: Record<string, StyleValue>;
  }

  interface Options {
    container: HTMLElement;
    elements: Array<{ data: NodeData } | { data: EdgeData }>;
    style: StyleRule[];
    layout: { name: string; animate?: boolean; padding?: number; nodeRepulsion?: number };
    minZoom?: number;
    maxZoom?: number;
    wheelSensitivity?: number;
    boxSelectionEnabled?: boolean;
  }

  interface Core {
    on(event: string, selector: string, handler: (event: EventObject) => void): void;
    destroy(): void;
  }
}

declare function cytoscape(options: cytoscape.Options): cytoscape.Core;
