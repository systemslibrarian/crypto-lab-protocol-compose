import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where
 * Exhibit 1 has already sealed both messages in all four compositions and
 * Exhibit 6 has already scored a design because `main.ts` clicks both buttons on
 * load; both skip links focused; Exhibit 1's seal retracted to four empty cards
 * by an edit, re-sealed, and then made IDENTICAL, which is the only route to the
 * equality leak the exhibit exists for; the MtE padding oracle run to a full
 * plaintext recovery and again at the input's 64-character maximum, its EtM
 * branch rejecting at the MAC, its idle reset, its empty-message validation
 * path, and its CBC-algebra explainer opened through its own summary; the naive
 * tag compare broken by timing and the constant-time compare holding, which is
 * the only state that reveals the real tag; a CRIME recovery from compressed
 * length and the blanked state after a new secret; all three TLS versions, one
 * per badge kind, plus the playing and paused walkthrough; and all five Exhibit
 * 6 verdicts. Every one of those states is scanned, in both themes, at desktop
 * and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page (this stylesheet
 * animates every `.panel` from `opacity: 0` under `animation-fill-mode: both`,
 * and `main.ts` branches all three attack renderers on the reduced-motion
 * preference it reads once at import), why no `<details>` is force-opened, why
 * the lab's defaults are asserted rather than assumed, and why `violations` is
 * not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
