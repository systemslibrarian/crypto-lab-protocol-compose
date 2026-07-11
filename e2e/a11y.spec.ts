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

async function scan(page: Page): Promise<void> {
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
