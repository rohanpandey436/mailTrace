import { html } from "../react.js";

export function logo(className = "") {
  return html`<svg class=${`logo${className ? ` ${className}` : ""}`} viewBox="0 0 32 32" aria-hidden="true">
    <rect class="logo__tile" width="32" height="32" rx="8" />
    <path class="logo__mark" d="M7.5 11v9.5a2 2 0 0 0 2 2h13a2 2 0 0 0 2-2V11M7.5 11l8.5 6.8L24.5 11" />
    <circle class="logo__ring" cx="16" cy="17.8" r="2.9" />
    <circle class="logo__dot" cx="16" cy="17.8" r="1.2" />
  </svg>`;
}
