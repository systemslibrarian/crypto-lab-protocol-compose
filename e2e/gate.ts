import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces (`e2e/a11y.spec.ts` as it stood before this commit):
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `neutralizeMotion()`
 *     pushed `animation-duration: 0s !important` and
 *     `transition-duration: 0s !important` through `addStyleTag` into every
 *     element and every pseudo-element. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     and here the block does work an injection cannot reproduce: it replaces
 *     `.panel`'s `animation: reveal 420ms ease both` with `animation: none`.
 *     `reveal` runs `opacity: 0 → 1` under `animation-fill-mode: both`, which is
 *     exactly the shape that strands an element invisible if a reduced-motion
 *     block cancels an animation without restoring its end state. Zeroing the
 *     DURATION leaves the animation in place and running, so the old gate could
 *     never have told the difference. `boot` asks for the real preference,
 *     ASSERTS it took effect, and `expectNotBlank` then measures the outcome in
 *     every driven state.
 *
 *     Reduced motion is not cosmetic on this page for a second reason: `main.ts`
 *     reads `matchMedia('(prefers-reduced-motion: reduce)')` ONCE at module load
 *     and branches all three attack renderers on it. With the preference set,
 *     Exhibit 2 skips the per-byte 0x00..0xFF sweep, Exhibit 3 skips the
 *     losing/winning bar race, and Exhibit 4 skips its 90ms inter-step pause.
 *     The old gate's style tag could not reach that branch at all, so the
 *     reduced-motion rendering of every attack — a genuinely different DOM, not
 *     a faster one — had never been scanned.
 *
 *  2. IT FORCE-REVEALED EVERY PANEL. `revealEverything()` set `open = true` on
 *     every `<details>` from script and stripped `hidden` from every element
 *     carrying it. This gate never touches `open` or `hidden`; both explainer
 *     disclosures are opened by clicking their own `<summary>`, which is also
 *     the only way to find out whether the summary is reachable and operable.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT, AFTER THE WHOLE DRIVE. `prepare()` ran
 *     all six exhibits and then called `scan()` a single time, so every state it
 *     built had already been overwritten by the next one before anything
 *     measured it — the MtE padding-oracle recovery, the EtM rejection, the
 *     naive-compare bar race, the CRIME size bar, and both TLS steps before the
 *     last. The light-theme test then toggled the theme WITHOUT RE-DRIVING, and
 *     nothing ever ran at phone width. This drive scans after every single step,
 *     in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: almost every
 *     surface here is a `color-mix()` (`.card`, `.hex`, `.repeat`, `.explainer`,
 *     `.oracle-mech`, `.mech-byte`, `.crime-secret`, `.tmg-bar`, `.code-block`
 *     are all `color-mix(in srgb, var(--panel) N%, var(--bg) M%)`, and every
 *     badge fill is a `color-mix(… , transparent)`), which axe declines to
 *     resolve and files under `incomplete`; and `aria-prohibited-attr`, where an
 *     `aria-label` on a role-less element lands, is `incomplete`-only too.
 *
 *  5. IT HAD NO REFLOW, KEYBOARD-SCROLLER OR GENERATED-CONTENT ORACLE. This page
 *     needs all three: `.code-block` is `white-space: pre; overflow-x: auto`
 *     around a nine-line C-like snippet whose longest line does not fit a 380px
 *     column, and it lives inside a `<details>` that a drive has to open before
 *     the scroller exists at all.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page is one declaration away from that defect and the check is what
 * makes "it is fine" a measurement. Every `.panel` — which is to say the intro,
 * the spectrum map and all six exhibits, i.e. the whole document — runs
 * `animation: reveal 420ms ease both`, and `reveal` starts at `opacity: 0`.
 * `both` includes `backwards`, so the 0 is painted before the animation starts
 * as well as held after it ends. The reduced-motion block writes
 * `animation: none`, which drops the fill along with the animation and returns
 * `.panel` to its declared `opacity: 1`; had it written `animation-duration: 0s`
 * instead — the spelling the old gate injected — the `both` fill would still
 * apply and the entire page would render blank for every reader with the
 * preference set. That distinction is why this runs in every state.
 *
 * `aria-hidden` subtrees are excluded, and on this page that exclusion has a
 * real cost worth stating: `#oracle-visual`, `#tmg-visual`, `#crime-visual`,
 * `#oracle-mech` and `#tls-dots` are all `aria-hidden="true"`. Their contents
 * are measured by the arithmetic contrast walk regardless (see `contrast.ts`,
 * which deliberately does NOT skip `aria-hidden`), so the gap here is narrow:
 * text that is BOTH removed from the accessibility tree AND painted at zero
 * opacity.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every exhibit here swallows its own exception into a `catch` that
 * writes a generic "Error: could not run…" line and calls `console.error`, so a
 * broken attack leaves a plausible-looking page behind and a gate that only
 * looks at the DOM reports green. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This page declares TWO — the shared `<header class="cl-topbar" role="banner">`
 * and `main.ts`'s own `<header class="cl-hero" role="banner">` — and the hero is
 * NOT scoped out of the banner role by nesting, because it sits before `<main>`
 * rather than inside it. So unlike some labs in this fleet, the single banner
 * here is produced by `index.html`'s `dedupeBanner()` demoting the hero to
 * `role="group"` at runtime. Asserting the OUTCOME rather than the mechanism
 * means both a change to that script and a change to the hero's markup are
 * caught.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Ordering matters twice over here: `main.ts`
 * captures `matchMedia('(prefers-reduced-motion: reduce)').matches` into a
 * module-level const at import time, so an emulation applied after `goto` would
 * change the CSS and not the JS, and the gate would then be scanning a page
 * whose stylesheet and whose renderers disagreed about what the reader asked
 * for.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')`, the shared bar's toggle writes
 * `localStorage.setItem('theme', …)`, and `main.ts`'s own (CSS-hidden)
 * `#theme-toggle` writes the same key. If any of those drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice — which is precisely what the gate this replaces
 * did for its first test, since it never seeded a theme at all and simply
 * trusted the default.
 *
 * The defaults are asserted at length because this lab does NOT arrive empty:
 * the last two statements in `main.ts` are `ex1Run?.click()` and
 * `chkRun?.click()`, so Exhibit 1 has already sealed both messages in all four
 * compositions and Exhibit 6 has already rendered a verdict before the reader
 * touches anything. Everything else — the padding oracle, the timing recovery,
 * the CRIME run — is idle. Asserting that mix is what stops a later change to
 * the auto-run turning half the scanned states into something else without
 * anyone noticing.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // The reduced-motion block's one job on this page, asserted rather than
  // assumed: `.panel`'s reveal animation is GONE, not merely fast. A zero
  // duration would leave `animation-fill-mode: both` holding `opacity: 0`.
  expect(
    await page.evaluate(() => getComputedStyle(document.querySelector('.panel')!).animationName),
    'reduced motion must cancel the panel reveal animation outright'
  ).toBe('none');

  // The whole page is built by `src/main.ts`, so a navigation that resolves
  // proves nothing at all about what is on screen.
  await expect(page.locator('#app .page')).toBeVisible();
  await expect(page.locator('section.panel')).toHaveCount(8);

  // ── Exhibit 1 and Exhibit 6 auto-run at module end; everything else is idle ──
  await expect(page.locator('#ex1-mte .badge')).toHaveCount(2);
  await expect(page.locator('#ex1-aead .badge')).toHaveCount(2);
  await expect(page.locator('#ex1-hint')).toHaveText(/A and B differ/);
  await expect(page.locator('#chk-output .badge')).toHaveCount(1);
  await expect(page.locator('#oracle-visual')).toHaveText('Press “Run the attack” to begin.');
  await expect(page.locator('#oracle-status')).toBeEmpty();
  await expect(page.locator('#tmg-visual')).toBeEmpty();
  await expect(page.locator('#tmg-status')).toBeEmpty();
  await expect(page.locator('#crime-visual')).toBeEmpty();
  await expect(page.locator('#crime-status')).toBeEmpty();
  await expect(page.locator('#oracle-mech')).toHaveClass(/mech-idle/);

  // ── Every shipped control default ────────────────────────────────────────
  await expect(page.locator('#ex1-a')).toHaveValue('transfer=2500&to=alice');
  await expect(page.locator('#ex1-b')).toHaveValue('transfer=2500&to=bob');
  await expect(page.locator('#oracle-mode')).toHaveValue('mte');
  await expect(page.locator('#oracle-message')).toHaveValue('pay=bob;amt=1337');
  await expect(page.locator('#tmg-mode')).toHaveValue('naive');
  await expect(page.locator('#chk-aead')).toHaveValue('yes');
  await expect(page.locator('#chk-etm')).toHaveValue('yes');
  await expect(page.locator('#chk-order')).toHaveValue('etm');
  await expect(page.locator('#tls-play')).toHaveAttribute('aria-pressed', 'false');

  // Both explainer disclosures ship shut. `revealEverything()` used to open them
  // from script; here they are only ever opened by clicking their summary.
  await expect(page.locator('details.explainer')).toHaveCount(2);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the old gate
 * never ran at a narrow viewport, so nothing here had ever been reflowed. The
 * shapes that break it on this page are the two-column `.msg-pair` grid, the
 * three-column `.three-grid` of composition cards, the sixteen-cell
 * `.mech-track` byte rows, the eight-cell `.tmg-track` of timing bars, and the
 * `white-space: pre` code block in Exhibit 3's explainer.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab has no scroller helper and no convention — `overflow` is written by
 * hand in five places in `style.css` (`.page`, `.hex`, `.tmg-bar`,
 * `.code-block`, `.sr-only`) — so this is the only thing standing between a new
 * `overflow-x: auto` and a region a keyboard cannot reach. It is also a check
 * that only bites in states a drive has to build: `.code-block` is inside a shut
 * `<details>` on arrival, and the three `.hex` output regions are empty until an
 * attack has been run in them.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * This is the old spec's `minimumControlBoundaryRatio` check, kept because the
 * idea was right, with its aim corrected and its vacuity removed.
 *
 * It queried `input:visible, select:visible, textarea:visible` — which is
 * EXACTLY the set `style.css` applies `--line-control` to, and applies it to
 * correctly (the rule is `textarea, input, select { border-color:
 * var(--line-control) }`, and the token's own comment says so). Pointing a check
 * only at the place a rule is already kept is the same as not having it. Every
 * BUTTON on this page — eleven of them, including the two that run the attacks —
 * keeps the softer `--line`, and none of them was ever measured.
 *
 * It was also structurally unfailable in a second way: it reduced with
 * `Math.min(...elements.map(…))`, and `Math.min()` of an empty list is
 * `Infinity`. Had the selector ever matched nothing — a renamed id, a panel that
 * failed to mount — the assertion `>= 3` would have passed on no measurements at
 * all. `scan` now asserts the sample is non-empty before judging it.
 *
 * A control passes if EITHER
 *   - its fill differs from the surface behind it, or
 *   - it has a border that stands out from the surface behind it AND from its
 *     own fill (how every control here works: a `--panel` fill with a drawn edge
 *     over a `color-mix()` panel).
 * so the score is `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 * Taking the max of the two mechanisms is what keeps this from failing a
 * perfectly delineated solid button for having no border.
 *
 * Two deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page
 *    disables `#oracle-run`, `#tmg-run`, `#crime-run` and `#crime-reset` for the
 *    duration of a running attack.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a copy — and its `.cl-btn` boundary
 *    measures 2.45:1 against the bar's fixed `#0b1512`. That is recorded in
 *    `nontext-baseline.ts` and reported upward rather than patched in one repo,
 *    so the exclusion is a decision and not an oversight.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex: this palette is full of
    // `color-mix()`, which `getComputedStyle` reports unchanged and which a
    // regex reads as null — landing the walk on the wrong backdrop. The old
    // check's `parse()` was exactly that regex, so every `color-mix()` surface
    // it met resolved to `[0,0,0]` and every ratio it computed against one was
    // fiction.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text'], input:not([type])")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden') return;
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0) {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * The wrapper is deliberately shaped so the real call cannot end up on the wrong
 * side of a `COLLECTING` guard: fleet-wide, `expectNoNewNonTextFailures` was
 * reachable only from inside `expectScrollersReachableSoft`, AFTER that
 * function's `if (!COLLECTING) return …`, so in a strict run — which is every
 * run in CI and every run anyone reads as a pass — `nontext.ts` never executed
 * at all. It is called from `scan()` here, at every driven state.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters more here than in most labs, since nearly
 *    every surface on this page is a `color-mix()` axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not finish
 *    — including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides, a defect that never reaches the violations array
 *    at all. That one is live here: `main.ts`'s `gloss()` puts an `aria-label`
 *    on a `<span>` and makes it legal with `role="note"`, and the role is easy
 *    to drop by accident.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast for interactive controls — SC 1.4.11, which axe has no
 *    rule for; see `auditControlBoundaries`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. Thirteen repos in this fleet had shipped that
  // form. Running the two sets separately and merging is the only way to have
  // both; the landmark four are wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the shape they catch — a shared sticky `<header role="banner">` above a
  // hero `<header role="banner">` that `dedupeBanner()` demotes at runtime, with
  // an `<aside role="complementary">` inside the hero.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Open one `<details class="explainer">` by clicking its summary, and assert it opened. */
async function openExplainer(page: Page, index: number): Promise<void> {
  const d = page.locator('details.explainer').nth(index);
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Drive the lab through every state it can render, scanning each.
 *
 * Six things shape this drive:
 *
 *  - IT DOES NOT ARRIVE EMPTY, AND THE ARRIVAL STATE IS SCANNED FIRST. `main.ts`
 *    ends by clicking `#ex1-run` and `#chk-run`, so four sealed compositions and
 *    a checklist verdict are already on screen. That is the first thing every
 *    reader sees and the old gate scanned it only after five more exhibits had
 *    been run over the top of it.
 *
 *  - EVERY BRANCH OF EVERY MODE FORK. Exhibit 2 forks on `#oracle-mode`
 *    (MtE recovers the plaintext, EtM rejects at the MAC), Exhibit 3 on
 *    `#tmg-mode` (naive compare is broken, constant-time holds and REVEALS the
 *    real tag in a rendering nothing else produces), and Exhibit 6 has five
 *    distinct verdicts behind three selects. All of them are driven, and each is
 *    scanned — the old gate ran two of Exhibit 2's branches and then threw both
 *    away by scanning only at the end.
 *
 *  - THE STATES THAT ONLY EXIST BETWEEN RUNS. Editing either message retracts
 *    Exhibit 1's seal to four EMPTY cards and a "Messages changed" hint;
 *    changing the oracle mode or the secret message resets Exhibit 2 to its
 *    idle diagram; changing the timing mode blanks Exhibit 3; "New secret"
 *    blanks Exhibit 4. Those four retracted renderings are what a reader sees
 *    for as long as they are reading the controls, and none of them had ever
 *    been scanned.
 *
 *  - THE ERROR PATH. Emptying `#oracle-message` and pressing run is the one
 *    state that renders "Enter a message before running the attack." — the only
 *    validation message in the lab.
 *
 *  - THE EQUALITY LEAK. `#ex1-match` is the only route to `.repeat-match`, the
 *    danger-tinted row that is the entire point of Exhibit 1, and to E&M's
 *    "identical tag" danger badge.
 *
 *  - NO FIXED TIMEOUTS. Every attack has a DOM completion signal — a status line
 *    that stops being empty, a run button returning from `disabled` — and the
 *    drive waits on those. Under reduced motion the renderers skip their
 *    per-step pauses entirely, so a fixed wait would be both wrong and slow.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, Exhibit 1 auto-sealed and Exhibit 6 auto-scored');

  // ── Both skip links, focused ──────────────────────────────────────────────
  // Two exist: the shared bar's `.cl-skip-link` (revealed by moving `top` from
  // -3rem to 0) and the lab's own `.skip-link` (revealed by moving `left` from
  // -10000px to 1rem, and only on `:focus-visible`). A keyboard Tab is the only
  // thing that produces either rendering.
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused');
  // Four more: the bar's brand link, its Menu and GitHub links, and then the
  // lab's own skip link, which is the first thing inside `#app`. It used to be
  // five — the bar's theme toggle sat between them until dark became the only
  // theme and the toggle was removed.
  for (let i = 0; i < 4; i += 1) await page.keyboard.press('Tab');
  await expect(page.locator('#app a.skip-link')).toBeFocused();
  await scanAt('lab skip link focused');
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());

  // ── Exhibit 1 — the four orders ───────────────────────────────────────────
  // Editing a message retracts the seal: four empty cards and a changed-hint.
  await page.locator('#ex1-b').fill('transfer=2500&to=carol');
  await expect(page.locator('#ex1-hint')).toHaveText(/Messages changed/);
  await expect(page.locator('#ex1-mte .badge')).toHaveCount(0);
  await scanAt('Exhibit 1 seal retracted, all four cards empty');

  await page.locator('#ex1-run').click();
  await expect(page.locator('#ex1-mte .badge')).toHaveCount(2);
  await expect(page.locator('#ex1-hint')).toHaveText(/A and B differ/);
  await scanAt('Exhibit 1 re-sealed, messages differ');

  // The only route to `.repeat-match` and E&M's equality-leak danger badge.
  await page.locator('#ex1-match').click();
  await expect(page.locator('#ex1-hint')).toHaveText(/A and B are identical/);
  await expect(page.locator('#ex1-eam .repeat-match')).toHaveCount(1);
  await scanAt('Exhibit 1 messages identical, E&M leaks equality');

  // ── Exhibit 2 — the padding oracle ────────────────────────────────────────
  // Default mode is MtE. This is the long one: a real byte-at-a-time recovery
  // that ends with `.mech-locked` and `.mech-hit` bytes across the diagram and
  // the recovered plaintext in `#oracle-visual`.
  await page.locator('#oracle-run').click();
  await expect(page.locator('#oracle-status')).toHaveClass(/verdict-danger/, { timeout: 120_000 });
  await expect(page.locator('#oracle-run')).toBeEnabled();
  await expect(page.locator('.mech-byte.mech-hit').first()).toBeVisible();
  await scanAt('Exhibit 2 MtE broken, plaintext recovered');

  await openExplainer(page, 0);
  await scanAt('Exhibit 2 CBC-algebra explainer open');

  await page.locator('#oracle-mode').selectOption('etm');
  await expect(page.locator('#oracle-status')).toBeEmpty();
  await expect(page.locator('#oracle-mech')).toHaveClass(/mech-idle/);
  await scanAt('Exhibit 2 reset to idle by the mode change');

  await page.locator('#oracle-run').click();
  await expect(page.locator('#oracle-status')).toHaveClass(/verdict-safe/);
  await expect(page.locator('#oracle-run')).toBeEnabled();
  await scanAt('Exhibit 2 EtM rejects tampering at the MAC');

  // The validation path — the only error message in the lab.
  await page.locator('#oracle-message').fill('');
  await page.locator('#oracle-run').click();
  await expect(page.locator('#oracle-status')).toHaveText(/Enter a message/);
  await scanAt('Exhibit 2 empty-message validation');

  // Restore a message and re-run MtE at the input's maximum length: 64
  // characters is four CBC blocks, which is the longest `.recovery` line and the
  // widest `#oracle-visual` this page can produce.
  await page.locator('#oracle-mode').selectOption('mte');
  await page.locator('#oracle-message').fill('x'.repeat(64));
  await page.locator('#oracle-run').click();
  await expect(page.locator('#oracle-status')).toHaveClass(/verdict-danger/, { timeout: 180_000 });
  await expect(page.locator('#oracle-run')).toBeEnabled();
  await scanAt('Exhibit 2 MtE at the 64-character maximum message length');

  // ── Exhibit 3 — the timing side-channel ───────────────────────────────────
  await page.locator('#tmg-run').click();
  await expect(page.locator('#tmg-status')).toHaveClass(/verdict-danger/, { timeout: 120_000 });
  await expect(page.locator('#tmg-run')).toBeEnabled();
  await scanAt('Exhibit 3 naive compare broken, tag recovered');

  await openExplainer(page, 1);
  await scanAt('Exhibit 3 constant-time explainer open, code block visible');

  // The code block is a horizontal scroller with no focusable content, so it
  // carries `tabindex="0"` to be operable at all (WCAG 2.1.1) — which makes it a
  // tab stop, and a tab stop has to show where focus is (WCAG 2.4.7). Focusing
  // it is the only state in which that ring is on screen to be measured.
  await page.locator('pre.code-block').focus();
  await expect(page.locator('pre.code-block')).toBeFocused();
  await scanAt('Exhibit 3 code block focused');

  await page.locator('#tmg-mode').selectOption('ct');
  await expect(page.locator('#tmg-visual')).toBeEmpty();
  await scanAt('Exhibit 3 cleared by the mode change');

  await page.locator('#tmg-run').click();
  await expect(page.locator('#tmg-status')).toHaveClass(/verdict-safe/, { timeout: 120_000 });
  await expect(page.locator('#tmg-run')).toBeEnabled();
  await scanAt('Exhibit 3 constant-time holds, real tag revealed');

  // ── Exhibit 4 — CRIME ─────────────────────────────────────────────────────
  // The run can legitimately end either way — a full recovery, or a stall on
  // compression noise — and both renderings are real states with different ink,
  // so the wait is on completion rather than on an outcome.
  await page.locator('#crime-run').click();
  await expect(page.locator('#crime-run')).toBeEnabled({ timeout: 120_000 });
  await expect(page.locator('#crime-status')).not.toBeEmpty();
  await expect(page.locator('.crime-run-match').first()).toBeVisible();
  await scanAt('Exhibit 4 CRIME run complete');

  await page.locator('#crime-reset').click();
  await expect(page.locator('#crime-status')).toBeEmpty();
  await scanAt('Exhibit 4 new secret drawn, output blanked');

  // ── Exhibit 5 — the TLS walkthrough ───────────────────────────────────────
  // Three versions, one per badge kind: `danger`, `warn`, `safe`. Stepping to
  // each is the only way any of the three badge inks reaches the TLS card, and
  // the dot row's active dot changes colour with it.
  for (const version of ['TLS 1.2', 'TLS 1.3', 'TLS 1.0 / 1.1']) {
    await page.locator('#tls-next').click();
    await expect(page.locator('#tls-card h3')).toHaveText(version);
    await scanAt(`Exhibit 5 showing ${version}`);
  }
  await page.locator('#tls-prev').click();
  await expect(page.locator('#tls-card h3')).toHaveText('TLS 1.3');
  await scanAt('Exhibit 5 stepped backwards to TLS 1.3');

  await page.locator('#tls-play').click();
  await expect(page.locator('#tls-play')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#tls-play')).toHaveText('Pause walkthrough');
  await scanAt('Exhibit 5 walkthrough playing');
  await page.locator('#tls-play').click();
  await expect(page.locator('#tls-play')).toHaveAttribute('aria-pressed', 'false');
  await scanAt('Exhibit 5 walkthrough paused');

  // ── Exhibit 6 — all five checklist verdicts ───────────────────────────────
  const VERDICTS: Array<[aead: string, etm: string, order: string, expected: RegExp]> = [
    ['yes', 'yes', 'etm', /Safe by design/],
    ['no', 'yes', 'etm', /Acceptable with care/],
    ['no', 'no', 'etm', /Order claimed, but not enforced/],
    ['no', 'yes', 'eam', /Vulnerable — Encrypt-and-MAC/],
    ['no', 'yes', 'mte', /Vulnerable — MAC-then-Encrypt/],
  ];
  for (const [aead, etm, order, expected] of VERDICTS) {
    await page.locator('#chk-aead').selectOption(aead);
    await page.locator('#chk-etm').selectOption(etm);
    await page.locator('#chk-order').selectOption(order);
    await page.locator('#chk-run').click();
    await expect(page.locator('#chk-output .badge')).toHaveText(expected);
    await scanAt(`Exhibit 6 verdict: aead=${aead} etm=${etm} order=${order}`);
  }
}
