// Real-browser accessibility audit: serves the production build with Vite preview,
// drives it with headless Chromium, and runs axe-core (WCAG 2.0/2.1 A + AA) in both
// themes after exercising the dynamic exhibits. Run `npm run build` first.
//
//   npm run build && npm run test:a11y
import { preview } from 'vite';
import { chromium } from 'playwright';
import { AxeBuilder } from '@axe-core/playwright';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const server = await preview({ preview: { port: 0 } });
const url = server.resolvedUrls.local[0];
const browser = await chromium.launch();
let total = 0;

try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.waitForSelector('#ex1-mte .badge');

  async function audit(label) {
    const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
    const serious = violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
    total += serious.length;
    if (violations.length === 0) {
      console.log(`PASS  ${label}: 0 violations`);
    } else {
      console.log(`${serious.length ? 'FAIL' : 'WARN'}  ${label}: ${violations.length} violation(s)`);
      for (const v of violations) {
        console.log(`   [${v.impact}] ${v.id} — ${v.help} (${v.nodes.length} node(s))`);
        console.log(`      ${v.helpUrl}`);
      }
    }
  }

  await audit('dark theme, initial');

  // Exercise the dynamic exhibits: reveal the E&M equality leak, run the timing
  // attack so its recovered output renders, open every explainer, and switch the
  // oracle to EtM. Then re-audit so axe sees the generated DOM too.
  await page.click('#ex1-match');
  await page.click('#tmg-run');
  await page.waitForSelector('#tmg-status.verdict-danger');
  const summaries = page.locator('.explainer summary');
  for (let i = 0; i < (await summaries.count()); i += 1) {
    await summaries.nth(i).click();
  }
  await page.selectOption('#oracle-mode', 'etm');
  await audit('dark theme, exhibits exercised');

  // Switch to light theme and re-audit (catches theme-specific contrast). The
  // shared header hides each lab's own #theme-toggle and drives the theme from
  // its own #cl-theme-toggle, so that is the control to click.
  await page.click('#cl-theme-toggle');
  await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
  await audit('light theme');

  console.log(total === 0 ? '\nAll audits passed (no serious/critical violations).' : `\n${total} serious/critical violation(s).`);
} finally {
  await browser.close();
  await server.httpServer.close();
}

process.exit(total === 0 ? 0 : 1);
