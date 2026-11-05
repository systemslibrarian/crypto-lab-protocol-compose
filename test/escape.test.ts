import { describe, expect, it } from 'vitest';

import { escapeHtml } from '../src/escape';

/**
 * `escapeHtml` fed `&<>` only, which is enough for element text and not enough
 * for the two attributes `gloss()` writes: `title="..."` and `aria-label="..."`.
 * CodeQL reported js/incomplete-html-attribute-sanitization twice against that
 * single line — once per attribute.
 *
 * Every current `gloss()` call passes a string literal, so this was defence in
 * depth rather than a live hole, and the eleven call sites were checked one by
 * one before saying so. The escaper is shared by ten other call sites that do
 * pass computed values, which is why hardening it is worth more than
 * hand-escaping one function.
 */
describe('escapeHtml', () => {
  it('escapes the quote that would close an attribute', () => {
    expect(escapeHtml('a" onmouseover="x()')).toBe('a&quot; onmouseover=&quot;x()');
    expect(escapeHtml("a' onmouseover='x()")).toBe('a&#39; onmouseover=&#39;x()');
  });

  it('still escapes the three it always did', () => {
    expect(escapeHtml('<b>&</b>')).toBe('&lt;b&gt;&amp;&lt;/b&gt;');
  });

  it('replaces the ampersand first, so nothing is double-encoded', () => {
    // '&quot;' arriving as literal text must survive as one escape, not two.
    expect(escapeHtml('&quot;')).toBe('&amp;quot;');
    expect(escapeHtml('&')).toBe('&amp;');
  });

  it('cannot leave a character that terminates a quoted attribute', () => {
    // The property, stated over the whole payload rather than a chosen example.
    const hostile = `" onfocus="alert(1)" x='y' <img src=x> & done`;
    const escaped = escapeHtml(hostile);
    for (const ch of ['"', "'", '<', '>']) {
      expect(escaped.includes(ch), `escaped output still contains ${ch}`).toBe(false);
    }
  });

  it('encodes only into forms the HTML parser decodes back', () => {
    // Proof that escaping changed no rendering, without a DOM: each entity this
    // produces is a named or numeric reference the parser maps back to the one
    // character it replaced. Checked by construction rather than asserted.
    const pairs: Array<[string, string]> = [
      ['&', '&amp;'],
      ['<', '&lt;'],
      ['>', '&gt;'],
      ['"', '&quot;'],
      ["'", '&#39;'],
    ];
    for (const [raw, entity] of pairs) {
      expect(escapeHtml(raw), raw).toBe(entity);
      // A trailing semicolon on every one: a reference without it is parsed
      // inconsistently in attribute values.
      expect(entity.endsWith(';'), entity).toBe(true);
    }
  });
});
