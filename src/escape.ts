/**
 * Escape for HTML text AND for a quoted attribute value.
 *
 * The quotes are the point. `gloss()` in main.ts puts this output inside
 * `title="..."` and `aria-label="..."`, and without them a value containing a
 * quote closes the attribute early — CodeQL
 * js/incomplete-html-attribute-sanitization, reported twice against that one
 * line because it has two such attributes.
 *
 * Escaping them changes nothing a reader sees: `&quot;` and `&#39;` render as
 * the characters themselves in text and in attribute values alike. `&` is
 * replaced first so nothing is double-encoded.
 *
 * It lives here rather than in main.ts so it can be tested at all: main.ts is
 * the entry module and builds the whole page on import.
 */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
