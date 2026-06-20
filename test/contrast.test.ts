import { describe, expect, it } from 'vitest';

// WCAG 2.1 contrast, computed from the same color tokens declared in src/style.css.
// Keep these values in sync with the :root / :root[data-theme='light'] blocks.
const DARK = {
  bg: '#08111d', panel: '#0f1f35', text: '#ecf2f9', muted: '#b7c7da',
  focus: '#5b9bd5', safe: '#4ec97a', warn: '#e3b341', danger: '#ff6b6b',
};
const LIGHT = {
  bg: '#eaf1f8', panel: '#ffffff', text: '#1a2d42', muted: '#4c647c',
  focus: '#2563eb', safe: '#136b2f', warn: '#8a5a00', danger: '#bd0e22',
};

type Rgb = [number, number, number];

function hexToRgb(hex: string): Rgb {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

/** color-mix(in srgb, fg p%, bg) — CSS mixes in gamma-encoded sRGB. */
function mix(fg: string, bg: string, p: number): Rgb {
  const a = hexToRgb(fg);
  const b = hexToRgb(bg);
  return [0, 1, 2].map((i) => a[i] * p + b[i] * (1 - p)) as Rgb;
}

function relLuminance([r, g, b]: Rgb): number {
  const lin = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function contrast(fg: Rgb | string, bg: Rgb | string): number {
  const lf = relLuminance(typeof fg === 'string' ? hexToRgb(fg) : fg);
  const lb = relLuminance(typeof bg === 'string' ? hexToRgb(bg) : bg);
  const [hi, lo] = lf > lb ? [lf, lb] : [lb, lf];
  return (hi + 0.05) / (lo + 0.05);
}

const AA = 4.5; // normal text

for (const [name, t] of [['dark', DARK], ['light', LIGHT]] as const) {
  describe(`contrast (${name} theme) meets WCAG AA`, () => {
    // Badge background is color-mix(in srgb, <color> 14%, transparent) over the panel.
    const badgeBg = (c: string) => mix(c, t.panel, 0.14);
    // .hex output background is color-mix(in srgb, panel 75%, bg 25%).
    const hexBg = mix(t.panel, t.bg, 0.75);

    it('body text on panel', () => expect(contrast(t.text, t.panel)).toBeGreaterThanOrEqual(AA));
    it('muted text on panel', () => expect(contrast(t.muted, t.panel)).toBeGreaterThanOrEqual(AA));
    it('link/focus on panel', () => expect(contrast(t.focus, t.panel)).toBeGreaterThanOrEqual(AA));

    it('safe badge text on its tint', () => expect(contrast(t.safe, badgeBg(t.safe))).toBeGreaterThanOrEqual(AA));
    it('warn badge text on its tint', () => expect(contrast(t.warn, badgeBg(t.warn))).toBeGreaterThanOrEqual(AA));
    it('danger badge text on its tint', () => expect(contrast(t.danger, badgeBg(t.danger))).toBeGreaterThanOrEqual(AA));

    it('recovered (safe) text on hex output', () => expect(contrast(t.safe, hexBg)).toBeGreaterThanOrEqual(AA));
    it('danger verdict text on panel', () => expect(contrast(t.danger, t.panel)).toBeGreaterThanOrEqual(AA));
    it('safe verdict text on panel', () => expect(contrast(t.safe, t.panel)).toBeGreaterThanOrEqual(AA));
  });
}
