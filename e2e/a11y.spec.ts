import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate. Serves the production preview build and runs
 * axe-core (WCAG 2.0/2.1 A + AA) in both themes after fully expanding and
 * exercising every interactive exhibit, asserting zero violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*, *::before, *::after {
      animation-duration: 0s !important;
      animation-delay: 0s !important;
      transition-duration: 0s !important;
      transition-delay: 0s !important;
    }`,
  });
}

async function revealEverything(page: Page): Promise<void> {
  // Open every native disclosure widget.
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any class-toggled / hidden panels so axe scans the generated DOM.
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('[hidden]'),
    )) {
      el.removeAttribute('hidden');
    }
  });
}

async function exerciseExhibits(page: Page): Promise<void> {
  // Ex1: force the E&M collision so its result badges render.
  await page.locator('#ex1-run').click();
  await page.locator('#ex1-match').click();

  // Ex2: padding oracle — run in both oracle modes so both status paths render.
  await page.selectOption('#oracle-mode', 'etm');
  await page.locator('#oracle-run').click();
  await page.selectOption('#oracle-mode', 'mte');
  await page.locator('#oracle-run').click();
  await page.waitForSelector('#oracle-status:not(:empty)');

  // Ex3: timing side-channel — recover the tag so the result region renders.
  await page.locator('#tmg-run').click();
  await page.waitForSelector('#tmg-status:not(:empty)');

  // Ex4: CRIME length attack.
  await page.locator('#crime-run').click();
  await page.waitForSelector('#crime-status:not(:empty)');

  // Ex5: step the TLS walkthrough so the region card populates.
  await page.locator('#tls-next').click();

  // Ex6: evaluate a design so the score output renders.
  await page.locator('#chk-run').click();
  await page.waitForSelector('#chk-output:not(:empty)');
}

/**
 * WCAG 1.4.11 (non-text contrast) regression for text-entry control boundaries.
 * Axe does not flag low-contrast control borders, so we measure them directly:
 * every visible input/select/textarea's rendered border color must reach 3:1
 * against both the control's own fill and the first opaque ancestor surface
 * behind it. Translucent colors are composited against those surfaces first.
 */
async function minimumControlBoundaryRatio(page: Page): Promise<number> {
  return page
    .locator('input:visible, select:visible, textarea:visible')
    .evaluateAll((elements) => {
      const parse = (value: string): { c: number[]; a: number } => {
        const n = (value.match(/[\d.]+/g) ?? ['0', '0', '0']).map(Number);
        return { c: n.slice(0, 3), a: n[3] ?? 1 };
      };
      const luminance = (parts: number[]): number => {
        const c = parts.map((part) => {
          const v = part / 255;
          return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * (c[0] ?? 0) + 0.7152 * (c[1] ?? 0) + 0.0722 * (c[2] ?? 0);
      };
      const ratio = (a: number[], b: number[]): number => {
        const [la, lb] = [luminance(a), luminance(b)];
        return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
      };
      const composite = (fg: number[], alpha: number, bg: number[]): number[] =>
        fg.map((v, i) => v * alpha + (bg[i] ?? 0) * (1 - alpha));
      const surfaceBehind = (el: Element): number[] => {
        for (let node = el.parentElement; node; node = node.parentElement) {
          const bg = parse(getComputedStyle(node).backgroundColor);
          if (bg.a >= 1) return bg.c;
        }
        return [255, 255, 255];
      };
      return Math.min(
        ...elements.map((el) => {
          const style = getComputedStyle(el);
          const exterior = surfaceBehind(el);
          const bg = parse(style.backgroundColor);
          const fill = bg.a >= 1 ? bg.c : composite(bg.c, bg.a, exterior);
          const b = parse(style.borderTopColor);
          const border = b.a >= 1 ? b.c : composite(b.c, b.a, fill);
          return Math.min(ratio(border, fill), ratio(border, exterior));
        }),
      );
    });
}

async function scan(page: Page): Promise<void> {
  expect(await minimumControlBoundaryRatio(page)).toBeGreaterThanOrEqual(3);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function prepare(page: Page): Promise<void> {
  await page.goto('.');
  await page.waitForSelector('#ex1-mte .badge');
  await neutralizeMotion(page);
  await exerciseExhibits(page);
  await revealEverything(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await prepare(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await scan(page);
});
