/**
 * A minimal element builder.
 *
 * Everything is built as real DOM rather than assembled as HTML strings, so
 * nothing on this page can be an injection site and every accessible name is
 * set as an attribute rather than concatenated into markup.
 */

export type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | number | boolean | undefined> = {},
  children: Child[] = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    node.setAttribute(key, String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: HTMLElement): HTMLElement {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/** A hex run that wraps rather than scrolling — long digests are everywhere here. */
export function hex(value: string, className = 'hexblock'): HTMLElement {
  return el('div', { class: className }, [value]);
}

/**
 * A labelled disclosure. This is where the depth goes: the byte-by-byte
 * inspector, the CBOR, the reset-authority table. Shut on arrival, which is
 * the state most readers stay in, and reachable by keyboard through its own
 * summary.
 */
export function disclosure(summary: string, body: Child[], className = ''): HTMLDetailsElement {
  const d = el('details', { class: `disclosure ${className}`.trim() }, [
    el('summary', {}, [summary]),
    el('div', { class: 'disclosure-body' }, body),
  ]);
  return d as HTMLDetailsElement;
}

export function card(title: string, children: Child[], className = ''): HTMLElement {
  return el('section', { class: `card ${className}`.trim() }, [
    el('h3', { class: 'card-title' }, [title]),
    ...children,
  ]);
}

export function button(
  label: string,
  onClick: () => void,
  attrs: Record<string, string | number | boolean | undefined> = {}
): HTMLButtonElement {
  const b = el('button', { type: 'button', class: 'btn', ...attrs }, [label]);
  b.addEventListener('click', onClick);
  return b as HTMLButtonElement;
}
