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

  // Open the CBC explainer and switch the oracle to EtM, then re-audit dark.
  await page.locator('.explainer summary').click();
  await page.selectOption('#oracle-mode', 'etm');
  await audit('dark theme, explainer open');

  // Switch to light theme and re-audit (catches theme-specific contrast).
  await page.click('#theme-toggle');
  await page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
  await audit('light theme');

  console.log(total === 0 ? '\nAll audits passed (no serious/critical violations).' : `\n${total} serious/critical violation(s).`);
} finally {
  await browser.close();
  await server.httpServer.close();
}

process.exit(total === 0 ? 0 : 1);
