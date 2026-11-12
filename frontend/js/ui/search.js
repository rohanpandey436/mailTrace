import { api } from "../api.js";
import { plural } from "../format.js";
import { categoryOf, severityOf } from "../labels.js";
import { Fragment, html, useEffect, useRef, useState } from "../react.js";
import { navigate } from "../router.js";
import { onListFilters, session, setListFilters } from "../state.js";
import { icon } from "./icons.js";

const MIN_CHARS = 2;
const WAIT_MS = 220;
const LIMIT = 6;
const LIST_ID = "search-suggestions";

export function SearchBox({ onSearch }) {
  const [query, setQuery] = useState(session.listFilters.q);
  const [open, setOpen] = useState(false);
  const [found, setFound] = useState((null));
  const [failed, setFailed] = useState(false);
  const [active, setActive] = useState(-1);
  const root = useRef((null));
  const input = useRef((null));
  const term = query.trim();
  const shown = open && term.length >= MIN_CHARS;
  const items = found ? found.items : [];

  useEffect(() => {
    setActive(-1);
    if (term.length < MIN_CHARS) {
      setFound(null);
      setFailed(false);
      return undefined;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      api.listEmails({ q: term, limit: LIMIT }).then(
        (page) => {
          if (cancelled) return;
          setFound({ items: page.items, total: page.total });
          setFailed(false);
        },
        () => {
          if (cancelled) return;
          setFound(null);
          setFailed(true);
        },
      );
    }, WAIT_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [term]);

  useEffect(() => onListFilters((filters) => setQuery((current) => (current.trim() === filters.q ? current : filters.q))), []);

  useEffect(() => {
    const close = () => setOpen(false);
    window.addEventListener("hashchange", close);
    return () => window.removeEventListener("hashchange", close);
  }, []);

  const leave = () => {
    setOpen(false);
    setActive(-1);
    input.current?.blur();
  };

  const showAll = () => {
    setListFilters({ ...session.listFilters, q: term, page: 0 });
    leave();
    onSearch();
    navigate("#/cases");
  };

  const openCase = (id) => {
    leave();
    navigate(`#/email/${encodeURIComponent(id)}`);
  };

  const onKeyDown = (event) => {
    if (event.key === "Escape") {
      if (!open) return;
      event.preventDefault();
      setOpen(false);
      setActive(-1);
      return;
    }
    if (!shown || items.length === 0) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((active + 1) % items.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive(active <= 0 ? items.length - 1 : active - 1);
    } else if (event.key === "Enter" && active >= 0) {
      event.preventDefault();
      openCase(items[active].id);
    }
  };

  const keepFocus = (event) => event.preventDefault();

  const results = () => {
    if (failed) return html`<div class="search__note">Search is not available right now. Try again in a moment.</div>`;
    if (!found) return html`<div class="search__note"><span class="spinner"></span>Searching…</div>`;
    if (items.length === 0) return html`<div class="search__note">No checked email matches “${term}”.</div>`;
    return html`<${Fragment}>
      <ul class="search__list" id=${LIST_ID} role="listbox" aria-label="Matching emails">
        ${items.map((item, index) => {
          const category = categoryOf(item.category);
          return html`<li
            key=${item.id}
            id=${`${LIST_ID}-${index}`}
            class=${`search__option${index === active ? " is-active" : ""}`}
            role="option"
            aria-selected=${String(index === active)}
            onMouseDown=${keepFocus}
            onMouseEnter=${() => setActive(index)}
            onClick=${() => openCase(item.id)}
          >
            <span class=${`search__score tone-${severityOf(item.severity).tone}`}>${item.risk_score}</span>
            <span class="search__text">
              <span class="search__subject truncate">${item.subject || "(no subject)"}</span>
              <span class="hint truncate">${category.label} · ${item.sender}</span>
            </span>
          </li>`;
        })}
      </ul>
      <button class="search__all" type="button" tabIndex=${-1} onMouseDown=${keepFocus} onClick=${showAll}>
        ${found.total > items.length ? `See all ${plural(found.total, "match", "matches")}` : "Open these in the full list"}
      </button>
    </>`;
  };

  return html`<form
    class="topbar__search search"
    role="search"
    ref=${root}
    onSubmit=${(event) => {
      event.preventDefault();
      showAll();
    }}
    onBlur=${(event) => {
      if (!(event.relatedTarget instanceof Node) || !root.current?.contains(event.relatedTarget)) setOpen(false);
    }}
  >
    <div class="search__field">
      ${icon("search", "search__icon")}
      <input
        ref=${input}
        class="input search__input"
        value=${query}
        placeholder="Search by subject, sender, IP address or domain…"
        autoComplete="off"
        spellCheck=${false}
        enterKeyHint="search"
        role="combobox"
        aria-label="Search checked emails"
        aria-autocomplete="list"
        aria-expanded=${String(shown)}
        aria-controls=${LIST_ID}
        aria-activedescendant=${shown && active >= 0 ? `${LIST_ID}-${active}` : undefined}
        onChange=${(event) => {
          setQuery(event.target.value);
          setOpen(true);
        }}
        onFocus=${() => setOpen(true)}
        onKeyDown=${onKeyDown}
      />
      ${query &&
      html`<button
        class="search__clear"
        type="button"
        aria-label="Clear the search"
        onClick=${() => {
          setQuery("");
          input.current?.focus();
        }}
      >
        ${icon("close")}
      </button>`}
    </div>
    ${shown && html`<div class="search__panel">${results()}</div>`}
  </form>`;
}
