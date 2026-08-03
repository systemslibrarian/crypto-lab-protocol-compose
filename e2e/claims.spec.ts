import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional regression gate for the Protocol Composition demo.
 *
 * The a11y spec proves the page is reachable and scannable; this one proves the
 * page is *right*. Every assertion is checked against something the page itself
 * rendered — the message in `#oracle-message` is the plaintext the padding
 * oracle must hand back, the number of tag cells is what the timed-guess counter
 * must be 256x, the secret in `#crime-secret` is what the length attack must
 * reproduce — so a wrong verdict cannot be papered over with a hardcoded string.
 * The claims the README makes are pinned end to end:
 *
 *   1. Exhibit 1 seals two messages in all four orders, and the equality verdict
 *      each card prints agrees with the two tag hexes printed right above it —
 *      E&M and only E&M snaps to one tag when the plaintexts match.
 *   2. Exhibit 2 recovers the typed message byte for byte from MtE with no key.
 *      The headline count, the query counter, and the "recovered message + N
 *      bytes of tag & padding" split all agree, and the split sums to the real
 *      CBC ciphertext length. Its live mechanism diagram sweeps the
 *      attacker-controlled byte and flips the matching plaintext byte, and the
 *      EtM / empty-message paths reach their own states naming their own cause.
 *   3. Exhibit 3's bars are the leak: each position's comparison count is >= the
 *      previous one, at least one byte longer than a wrong guess would run, and
 *      drives the bar height. Constant-time mode recovers nothing and says so.
 *   4. Exhibit 4 recovers the session secret from compressed length alone, with
 *      queries == secret length x alphabet size, and the recovered string,
 *      the reflected-request panel and the verdict all agreeing on the outcome.
 *   5. Exhibits 5 and 6 (TLS walkthrough, checklist) are self-consistent: the
 *      active dot's safety class matches the badge on the card it points at, and
 *      every branch of the checklist is reachable and names its cause.
 *   6. Stale state is retracted: editing either Exhibit 1 message or the oracle's
 *      configuration takes the previous verdict down instead of leaving it
 *      standing over inputs it was never computed from (both were live bugs).
 */

const CRIME_ALPHABET_SIZE = 36; // src/crime.ts: [a-z0-9]
const TAG_BYTE_VALUES = 256; // one timed guess per possible byte value

/** "8,885" -> 8885. Fails loudly rather than yielding NaN. */
function count(raw: string | null): number {
  const digits = (raw ?? '').replace(/[,\s]/g, '');
  expect(digits).toMatch(/^\d+$/);
  return Number(digits);
}

async function text(scope: Page | Locator, selector: string): Promise<string> {
  return ((await scope.locator(selector).textContent()) ?? '').trim();
}

/** AES-CBC ciphertext length for `plaintextBytes` + a 32-byte HMAC tag. */
function cbcLength(plaintextBytes: number): number {
  return 16 * Math.ceil((plaintextBytes + 32 + 1) / 16);
}

interface RepeatRow {
  a: string;
  b: string;
  flaggedEqual: boolean;
  label: string;
  verdict: string;
  verdictClass: string;
}

/**
 * Read one Exhibit 1 card: the two hex strings it printed for messages A and B,
 * whether it flagged them as identical, and the equality badge it drew. The page
 * shortens anything over 16 bytes to `32 hex chars + …`, so both halves are
 * compared on the same displayed prefix.
 */
async function repeatRow(page: Page, cardId: string): Promise<RepeatRow> {
  const row = page.locator(`${cardId} .repeat`);
  const codes = await row.locator('code').allTextContents();
  expect(codes).toHaveLength(2);
  const strip = (value: string): string => value.replace(/^msg [AB]:\s*/, '').replace(/…$/, '');
  const [a, b] = codes.map(strip);
  expect(a).toMatch(/^[0-9a-f]{32}$/);
  expect(b).toMatch(/^[0-9a-f]{32}$/);
  const badge = page.locator(`${cardId} .card-body .badge`).first();
  return {
    a,
    b,
    flaggedEqual: ((await row.getAttribute('class')) ?? '').includes('repeat-match'),
    label: await text(page, `${cardId} .repeat-label`),
    verdict: ((await badge.textContent()) ?? '').trim(),
    verdictClass: (await badge.getAttribute('class')) ?? '',
  };
}

interface TimingCell {
  hex: string;
  ran: number;
  outOf: number;
  heightPct: number;
}

async function timingCells(page: Page): Promise<TimingCell[]> {
  return page.locator('#tmg-visual .tmg-cell').evaluateAll((cells) =>
    cells.map((cell) => {
      const readout = cell.querySelector('.tmg-readout')?.textContent ?? '';
      const match = /ran (\d+)\/(\d+)/.exec(readout);
      const height = /height:\s*(\d+)%/.exec(
        cell.querySelector<HTMLElement>('.tmg-bar-fill')?.getAttribute('style') ?? '',
      );
      return {
        hex: (cell.querySelector('code')?.textContent ?? '').trim(),
        ran: match ? Number(match[1]) : -1,
        outOf: match ? Number(match[2]) : -1,
        heightPct: height ? Number(height[1]) : -1,
      };
    }),
  );
}

async function runOracle(page: Page): Promise<void> {
  await page.locator('#oracle-run').click();
  await expect(page.locator('#oracle-status')).not.toBeEmpty({ timeout: 120_000 });
  await expect(page.locator('#oracle-run')).toBeEnabled({ timeout: 120_000 });
}

// Uncaught page exceptions fail the test that provoked them. Reset per test; a
// worker only ever runs one test at a time, so this stays test-scoped.
let pageErrors: string[] = [];

test.beforeEach(async ({ page }) => {
  pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto('.');
  // Exhibit 1 auto-runs at load; its badges are the signal that WebCrypto came
  // up and the page finished its first seal.
  await expect(page.locator('#ex1-mte .card-body .badge').first()).toBeVisible();
});

test.afterEach(() => {
  expect(pageErrors).toEqual([]);
});

// ---------------------------------------------------------------------------
// Exhibit 1 — the four orders side by side.
// ---------------------------------------------------------------------------

test('every card equality verdict follows the two hexes printed above it', async ({ page }) => {
  await expect(page.locator('#ex1-hint')).toContainText('A and B differ');

  for (const cardId of ['#ex1-mte', '#ex1-etm', '#ex1-eam', '#ex1-aead']) {
    const row = await repeatRow(page, cardId);
    // Distinct messages under distinct random IVs: nothing may repeat, and the
    // "identical across A and B" flag must agree with the hexes on screen.
    expect(row.a).not.toBe(row.b);
    expect(row.flaggedEqual).toBe(false);
    expect(row.label).not.toContain('identical');
    expect(row.verdictClass).toContain('badge-safe');
  }
  // Only MtE hides its tag inside the ciphertext; the other three publish one.
  expect(await text(page, '#ex1-mte .repeat-label')).toBe('ciphertext');
  for (const cardId of ['#ex1-etm', '#ex1-eam', '#ex1-aead']) {
    expect(await text(page, `${cardId} .repeat-label`)).toBe('tag');
  }
});

test('identical messages leak through E&M alone, and the badge names the leak', async ({ page }) => {
  await page.locator('#ex1-match').click();
  await expect(page.locator('#ex1-hint')).toContainText('A and B are identical');
  expect(await page.locator('#ex1-b').inputValue()).toBe(await page.locator('#ex1-a').inputValue());

  // E&M MACs the plaintext, so equal plaintexts collapse to one tag — the whole
  // point of the exhibit. The page must both print equal hexes and say so.
  const eam = await repeatRow(page, '#ex1-eam');
  expect(eam.a).toBe(eam.b);
  expect(eam.flaggedEqual).toBe(true);
  expect(eam.label).toContain('identical across A and B');
  expect(eam.verdictClass).toContain('badge-danger');
  expect(eam.verdict).toContain('attacker learns A and B are the same message');

  // Everything else stays different, because a fresh random IV/nonce feeds it.
  for (const cardId of ['#ex1-mte', '#ex1-etm', '#ex1-aead']) {
    const row = await repeatRow(page, cardId);
    expect(row.a).not.toBe(row.b);
    expect(row.flaggedEqual).toBe(false);
    expect(row.verdictClass).toContain('badge-safe');
  }
});

test('editing a message retracts the seal instead of leaving a stale verdict', async ({ page }) => {
  // Regression: the cards and the hint are verdicts about the text that was
  // sealed. Before the fix, "A and B are identical" and E&M's "identical tag"
  // risk badge stayed up over two textareas the reader could see differed.
  await page.locator('#ex1-match').click();
  await expect(page.locator('#ex1-hint')).toContainText('A and B are identical');

  await page.locator('#ex1-b').fill('transfer=2500&to=mallory');
  await expect(page.locator('#ex1-hint')).toContainText('Messages changed');
  for (const cardId of ['#ex1-mte', '#ex1-etm', '#ex1-eam', '#ex1-aead']) {
    await expect(page.locator(`${cardId} .card-body`)).toBeEmpty();
  }

  // And re-sealing recomputes rather than restoring the retracted verdict.
  await page.locator('#ex1-run').click();
  await expect(page.locator('#ex1-hint')).toContainText('A and B differ');
  const eam = await repeatRow(page, '#ex1-eam');
  expect(eam.a).not.toBe(eam.b);
  expect(eam.flaggedEqual).toBe(false);
});

// ---------------------------------------------------------------------------
// Exhibit 2 — the padding oracle. Runs with motion reduced so the demo takes its
// no-animation path: the recovery itself is identical, and the assertions are
// about the recovered bytes, not the frame rate. One animated test below covers
// the mechanism diagram the README promises.
// ---------------------------------------------------------------------------

test.describe('padding oracle (reduced motion)', () => {
  // MUST be emulateMedia: on Playwright 1.61.1 test.use({ reducedMotion }) never
  // reaches the page (matchMedia still reports false), so the animations these
  // assertions are meant to skip kept running at full speed.
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    expect(
      await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
      'reduced-motion emulation did not reach the page',
    ).toBe(true);
  });

  test('MtE hands back exactly the message that was typed, and the counts add up', async ({ page }) => {
    await page.locator('#oracle-message').fill('pay=mallory;amt=99');
    const secret = await page.locator('#oracle-message').inputValue();
    const secretBytes = new TextEncoder().encode(secret).length;

    await runOracle(page);

    // The headline verdict, checked against the page's own input: the attacker
    // reconstructed the plaintext with no key.
    await expect(page.locator('#oracle-status')).toHaveClass(/verdict-danger/);
    await expect(page.locator('#oracle-status')).toContainText('MtE broken');
    expect(await text(page, '#oracle-visual .recovery-text')).toBe(secret);

    // The two numbers on screen are the same number, and it is a plausible
    // number of oracle queries for this ciphertext: at least one per byte, at
    // most a full 0x00..0xFF sweep plus the disambiguation probe per byte.
    const total = cbcLength(secretBytes);
    const queries = count(await text(page, '#oracle-status .stat'));
    expect(count(await text(page, '#oracle-counter .counter-num'))).toBe(queries);
    expect(queries).toBeGreaterThanOrEqual(total);
    expect(queries).toBeLessThanOrEqual(total * (TAG_BYTE_VALUES + 2));

    // Parts sum to the whole: the readable message plus the "+ N bytes of HMAC
    // tag & CBC padding" tail is the entire CBC ciphertext, so nothing was left
    // unrecovered behind the claim of a full break.
    const extra = count(/\+\s*([\d,]+)\s*bytes/.exec(await text(page, '#oracle-visual .recovery-extra'))?.[1] ?? '');
    expect(secretBytes + extra).toBe(total);
    expect(extra).toBeGreaterThanOrEqual(32); // the sealed HMAC-SHA-256 tag
    await expect(page.locator('#oracle-visual .pending')).toHaveCount(0);

    // The mechanism diagram settles on block 0 with all 16 bytes locked in, and
    // the plaintext track spells the start of the stolen message.
    await expect(page.locator('#oracle-mech')).not.toHaveClass(/mech-idle/);
    await expect(page.locator('#mech-cprev .mech-locked')).toHaveCount(16);
    await expect(page.locator('#mech-plain .mech-hit')).toHaveCount(16);
    await expect(page.locator('#mech-plain .mech-pending')).toHaveCount(0);
    const glyphs = (await page.locator('#mech-plain .mech-byte').allTextContents()).join('');
    expect(glyphs.slice(0, 16)).toBe(secret.slice(0, 16));
  });

  test('EtM rejects the tamper at the MAC, leaking nothing to query', async ({ page }) => {
    await page.selectOption('#oracle-mode', 'etm');
    await runOracle(page);

    await expect(page.locator('#oracle-status')).toHaveClass(/verdict-safe/);
    await expect(page.locator('#oracle-status')).toContainText('EtM safe');
    // The cause is named: the MAC covers the ciphertext and is checked first.
    await expect(page.locator('#oracle-status')).toContainText('checked first');
    await expect(page.locator('#oracle-visual')).toContainText('rejected at the MAC');
    await expect(page.locator('#oracle-visual')).toContainText('0 bytes leaked');
    expect(count(await text(page, '#oracle-counter .counter-num'))).toBe(0);
    await expect(page.locator('#oracle-counter')).toContainText('oracle queries possible');

    // Nothing was recovered, so the mechanism diagram must not imply a leak.
    await expect(page.locator('#oracle-mech')).toHaveClass(/mech-idle/);
    await expect(page.locator('#mech-plain .mech-hit')).toHaveCount(0);
    await expect(page.locator('#mech-plain .mech-pending')).toHaveCount(16);
  });

  test('an empty message is refused without claiming a break', async ({ page }) => {
    await page.locator('#oracle-message').fill('   ');
    await runOracle(page);

    await expect(page.locator('#oracle-status')).toHaveText('Enter a message before running the attack.');
    await expect(page.locator('#oracle-status')).not.toHaveClass(/verdict-/);
    await expect(page.locator('#oracle-visual')).toBeEmpty();
    await expect(page.locator('#oracle-counter')).toBeEmpty();
  });

  test('changing the configuration retracts the previous oracle verdict', async ({ page }) => {
    // Regression: "✗ MtE broken: full plaintext recovered … pay=bob;amt=1337"
    // used to stay on screen — with its query count and the mechanism diagram
    // frozen on the stolen bytes — after the composition select flipped to the
    // one labelled "safe", or after the message it named was edited.
    await runOracle(page);
    await expect(page.locator('#oracle-status')).toHaveClass(/verdict-danger/);

    await page.selectOption('#oracle-mode', 'etm');
    await expect(page.locator('#oracle-status')).toBeEmpty();
    await expect(page.locator('#oracle-status')).not.toHaveClass(/verdict-/);
    await expect(page.locator('#oracle-counter')).toBeEmpty();
    await expect(page.locator('#oracle-visual')).toHaveText('Press “Run the attack” to begin.');
    await expect(page.locator('#oracle-mech')).toHaveClass(/mech-idle/);
    await expect(page.locator('#mech-plain .mech-hit')).toHaveCount(0);

    // Same for the secret message: run again, then retype it.
    await page.selectOption('#oracle-mode', 'mte');
    await runOracle(page);
    await expect(page.locator('#oracle-status')).toHaveClass(/verdict-danger/);
    await page.locator('#oracle-message').fill('pay=carol;amt=1');
    await expect(page.locator('#oracle-status')).toBeEmpty();
    await expect(page.locator('#oracle-visual')).not.toContainText('recovered message');
    await expect(page.locator('#oracle-mech')).toHaveClass(/mech-idle/);

    // The control is still live afterwards — the retraction does not dead-end it.
    await runOracle(page);
    expect(await text(page, '#oracle-visual .recovery-text')).toBe('pay=carol;amt=1');
  });
});

test('the mechanism diagram sweeps the attacked byte while the attack runs', async ({ page }) => {
  // README: the live CBC diagram "lights up the attacker-controlled byte and
  // flips the matching plaintext byte green in step with the recovery". Run at
  // full motion so the sweep actually happens; a short message keeps it brief.
  await page.locator('#oracle-message').fill('hi');
  await page.locator('#oracle-run').click();

  // Exactly one byte is lit at a time, and the plaintext track is still filling
  // in while it is — i.e. the diagram is driven in step with the recovery rather
  // than painted once at the end. Both facts are read in the same tick so the
  // pair cannot be satisfied by two different moments of the run.
  await page.waitForFunction(
    () =>
      document.querySelectorAll('#mech-cprev .mech-sweeping').length === 1 &&
      document.querySelectorAll('#mech-plain .mech-hit').length < 16,
    null,
    { timeout: 30_000 },
  );

  await expect(page.locator('#oracle-status')).toContainText('MtE broken', { timeout: 120_000 });
  await expect(page.locator('#mech-cprev .mech-sweeping')).toHaveCount(0);
  await expect(page.locator('#mech-plain .mech-hit')).toHaveCount(16);
  const glyphs = (await page.locator('#mech-plain .mech-byte').allTextContents()).join('');
  expect(glyphs.startsWith('hi')).toBe(true);
});

// ---------------------------------------------------------------------------
// Exhibit 3 — timing side-channel on the tag comparison.
// ---------------------------------------------------------------------------

test.describe('timing side-channel (reduced motion)', () => {
  // MUST be emulateMedia: on Playwright 1.61.1 test.use({ reducedMotion }) never
  // reaches the page (matchMedia still reports false), so the animations these
  // assertions are meant to skip kept running at full speed.
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    expect(
      await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
      'reduced-motion emulation did not reach the page',
    ).toBe(true);
  });

  test('the naive compare gives up the whole tag, and the bars are the leak', async ({ page }) => {
    expect(await text(page, '#tmg-secret')).toMatch(/^(?:·· ){7}··$/); // 8 masked bytes
    await page.locator('#tmg-run').click();
    await expect(page.locator('#tmg-status')).toContainText('Naive compare broken', { timeout: 60_000 });
    await expect(page.locator('#tmg-status')).toHaveClass(/verdict-danger/);

    const cells = await timingCells(page);
    expect(cells).toHaveLength(8);
    const total = cells.length;

    cells.forEach((cell, i) => {
      expect(cell.hex).toMatch(/^[0-9a-f]{2}$/);
      expect(cell.outOf).toBe(total);
      // A wrong guess stops at byte i+1; the winner runs at least one further.
      expect(cell.ran).toBeGreaterThanOrEqual(Math.min(i + 2, total));
      expect(cell.ran).toBeLessThanOrEqual(total);
      // Bar height IS the comparison count, to the same rounding the page uses.
      expect(cell.heightPct).toBe(Math.round((cell.ran / total) * 100));
      // Rows chain: each recovered byte lets the compare run at least as far as
      // the one before it did.
      if (i > 0) expect(cell.ran).toBeGreaterThanOrEqual(cells[i - 1].ran);
    });
    // The last byte lets the compare run to completion — that is the match.
    expect(cells[total - 1].ran).toBe(total);

    // Headline count == counter == one timed guess per byte value per position.
    const queries = count(await text(page, '#tmg-status .stat'));
    expect(queries).toBe(total * TAG_BYTE_VALUES);
    expect(count(await text(page, '#tmg-counter .counter-num'))).toBe(queries);
  });

  test('the constant-time compare recovers nothing and proves it by revealing the tag', async ({ page }) => {
    await page.selectOption('#tmg-mode', 'ct');
    await page.locator('#tmg-run').click();
    await expect(page.locator('#tmg-status')).toContainText('Constant-time compare holds', { timeout: 60_000 });
    await expect(page.locator('#tmg-status')).toHaveClass(/verdict-safe/);
    await expect(page.locator('#tmg-status')).toContainText('recovers nothing');

    const revealed = await text(page, '#tmg-status code');
    expect(revealed).toMatch(/^[0-9a-f]{16}$/);

    const cells = await timingCells(page);
    expect(cells).toHaveLength(8);
    // Flat bars: every guess costs the same work, so there is no signal at all.
    for (const cell of cells) {
      expect(cell.ran).toBe(cells.length);
      expect(cell.heightPct).toBe(100);
    }
    // The cells show the tag the status revealed, not something "recovered".
    expect(cells.map((c) => c.hex).join('')).toBe(revealed);
    // Same work spent as the naive run — the cost is identical, the leak is not.
    expect(count(await text(page, '#tmg-counter .counter-num'))).toBe(cells.length * TAG_BYTE_VALUES);
  });

  test('switching comparison mode retracts the verdict and draws a fresh tag', async ({ page }) => {
    await page.locator('#tmg-run').click();
    await expect(page.locator('#tmg-status')).toContainText('Naive compare broken', { timeout: 60_000 });

    await page.selectOption('#tmg-mode', 'ct');
    await expect(page.locator('#tmg-status')).toBeEmpty();
    await expect(page.locator('#tmg-status')).not.toHaveClass(/verdict-/);
    await expect(page.locator('#tmg-counter')).toBeEmpty();
    await expect(page.locator('#tmg-visual')).toBeEmpty();

    // The next run must attack a newly drawn tag, not replay the recovered one.
    await page.locator('#tmg-run').click();
    await expect(page.locator('#tmg-status')).toContainText('Constant-time compare holds', { timeout: 60_000 });
  });
});

// ---------------------------------------------------------------------------
// Exhibit 4 — CRIME: recovery from compressed length alone.
// ---------------------------------------------------------------------------

test.describe('CRIME length leak (reduced motion)', () => {
  // MUST be emulateMedia: on Playwright 1.61.1 test.use({ reducedMotion }) never
  // reaches the page (matchMedia still reports false), so the animations these
  // assertions are meant to skip kept running at full speed.
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    expect(
      await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
      'reduced-motion emulation did not reach the page',
    ).toBe(true);
  });

  test('the session secret falls out of the compressed length alone', async ({ page }) => {
    const secret = (await text(page, '#crime-secret')).replace(/^session=/, '');
    expect(secret).toMatch(/^[a-z0-9]{8}$/);

    await page.locator('#crime-run').click();
    await expect(page.locator('#crime-status')).toContainText(/recovered|stalled/, { timeout: 120_000 });

    const guessed = await text(page, '#crime-visual .recovery-text');
    expect(guessed).toHaveLength(secret.length);
    // The reflected-request panel shows the true secret above the attacker's
    // reconstruction, so the two runs must be exactly those two strings.
    expect(await text(page, '#crime-secret-run')).toBe(secret);
    expect(await text(page, '#crime-guess-run')).toBe(guessed);

    // One length measurement per alphabet character per position, every run.
    const queries = count(await text(page, '#crime-counter .counter-num'));
    expect(queries).toBe(secret.length * CRIME_ALPHABET_SIZE);

    if (guessed === secret) {
      await expect(page.locator('#crime-status')).toHaveClass(/verdict-danger/);
      await expect(page.locator('#crime-status')).toContainText('Full secret recovered');
      expect(count(await text(page, '#crime-status .stat'))).toBe(queries);
      // The winning blob's size is reported, and it is a real byte count.
      const size = await text(page, '#crime-sizebar .crime-size-val');
      expect(size).toMatch(/^\d+ bytes$/);
      expect(count(/(\d+)/.exec(size)![1])).toBeGreaterThan(0);
      await expect(page.locator('#crime-visual .pending')).toHaveCount(0);
    } else {
      // Compression noise tied two characters: the page must own the stall
      // rather than claim a recovery it did not make.
      await expect(page.locator('#crime-status')).not.toHaveClass(/verdict-danger/);
      await expect(page.locator('#crime-status')).toContainText('stalled on compression noise');
    }
  });

  test('New secret draws a different secret and clears the previous recovery', async ({ page }) => {
    const first = await text(page, '#crime-secret');
    await page.locator('#crime-run').click();
    await expect(page.locator('#crime-status')).toContainText(/recovered|stalled/, { timeout: 120_000 });
    await expect(page.locator('#crime-reset')).toBeEnabled();

    await page.locator('#crime-reset').click();
    expect(await text(page, '#crime-secret')).not.toBe(first);
    await expect(page.locator('#crime-status')).toBeEmpty();
    await expect(page.locator('#crime-visual')).toBeEmpty();
    await expect(page.locator('#crime-counter')).toBeEmpty();
    await expect(page.locator('#crime-sizebar')).toBeEmpty();
    // The reflected panel is re-masked: nothing of the new secret is on screen.
    await expect(page.locator('#crime-secret-run .crime-run-match')).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// Exhibit 5 — TLS walkthrough.
// ---------------------------------------------------------------------------

test('the TLS walkthrough steps danger -> warn -> safe, dot matching badge', async ({ page }) => {
  const dots = page.locator('#tls-dots .tls-dot');
  await expect(dots).toHaveCount(3);
  await expect(page.locator('#tls-dots .tls-dot-danger')).toHaveCount(1);
  await expect(page.locator('#tls-dots .tls-dot-warn')).toHaveCount(1);
  await expect(page.locator('#tls-dots .tls-dot-safe')).toHaveCount(1);

  const seen: string[] = [];
  for (let step = 0; step < 3; step += 1) {
    const classes = await dots.evaluateAll((els) => els.map((el) => el.className));
    const activeIndex = classes.findIndex((c) => c.includes('tls-dot-active'));
    expect(activeIndex).toBe(step);
    // The safety the dot advertises is the safety the card badges.
    const safety = /tls-dot-(danger|warn|safe)/.exec(classes[activeIndex])![1];
    await expect(page.locator('#tls-card .badge')).toHaveClass(new RegExp(`badge-${safety}`));
    seen.push(safety);
    const version = await text(page, '#tls-card h3');
    expect(version).toMatch(/^TLS /);
    for (const field of ['Composition:', 'Observed outcome:', 'Lesson:']) {
      await expect(page.locator('#tls-card')).toContainText(field);
    }
    await page.locator('#tls-next').click();
  }
  expect(seen).toEqual(['danger', 'warn', 'safe']);
  // Next wrapped back to the start; Previous wraps the other way.
  await expect(page.locator('#tls-dots .tls-dot').first()).toHaveClass(/tls-dot-active/);
  await page.locator('#tls-prev').click();
  await expect(page.locator('#tls-dots .tls-dot').nth(2)).toHaveClass(/tls-dot-active/);
});

test('play advances the walkthrough and pause actually stops it', async ({ page }) => {
  const version = () => text(page, '#tls-card h3');
  const before = await version();

  await page.locator('#tls-play').click();
  await expect(page.locator('#tls-play')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#tls-play')).toHaveText('Pause walkthrough');
  // Auto-advance must not spam the live region; manual stepping still announces.
  await expect(page.locator('#tls-card')).toHaveAttribute('aria-live', 'off');
  await expect.poll(version, { timeout: 15_000 }).not.toBe(before);

  await page.locator('#tls-play').click();
  await expect(page.locator('#tls-play')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#tls-play')).toHaveText('Play walkthrough');
  await expect(page.locator('#tls-card')).toHaveAttribute('aria-live', 'polite');
  const paused = await version();
  await page.waitForTimeout(2500); // longer than the 1800ms auto-advance interval
  expect(await version()).toBe(paused);
});

// ---------------------------------------------------------------------------
// Exhibit 6 — the protocol safety checklist.
// ---------------------------------------------------------------------------

test('the checklist reaches every verdict it can give, naming the cause', async ({ page }) => {
  const cases: Array<{
    aead: string;
    etm: string;
    order: string;
    kind: 'safe' | 'warn' | 'danger';
    verdict: string;
    cause: RegExp;
  }> = [
    { aead: 'yes', etm: 'yes', order: 'etm', kind: 'safe', verdict: 'Safe by design', cause: /nonce/ },
    { aead: 'no', etm: 'yes', order: 'etm', kind: 'warn', verdict: 'Acceptable with care', cause: /constant-time tag comparison/ },
    { aead: 'no', etm: 'no', order: 'etm', kind: 'danger', verdict: 'Order claimed, but not enforced', cause: /decrypt-first oracle/ },
    { aead: 'no', etm: 'yes', order: 'eam', kind: 'danger', verdict: 'Vulnerable — Encrypt-and-MAC', cause: /leaks message equality/ },
    { aead: 'no', etm: 'yes', order: 'mte', kind: 'danger', verdict: 'Vulnerable — MAC-then-Encrypt', cause: /padding-oracle surface/ },
  ];

  for (const scenario of cases) {
    await page.selectOption('#chk-aead', scenario.aead);
    await page.selectOption('#chk-etm', scenario.etm);
    await page.selectOption('#chk-order', scenario.order);
    await page.locator('#chk-run').click();

    const badge = page.locator('#chk-output .badge');
    await expect(badge).toHaveClass(new RegExp(`badge-${scenario.kind}`));
    await expect(badge).toContainText(scenario.verdict);
    await expect(page.locator('#chk-output .note')).toHaveText(scenario.cause);
  }

  // AEAD short-circuits the ordering questions rather than contradicting them:
  // the same "safe" verdict stands even with the worst order selected.
  await page.selectOption('#chk-aead', 'yes');
  await page.selectOption('#chk-etm', 'no');
  await page.selectOption('#chk-order', 'mte');
  await page.locator('#chk-run').click();
  await expect(page.locator('#chk-output .badge')).toHaveClass(/badge-safe/);
});

// ---------------------------------------------------------------------------
// Shareable configuration (README: "the current configuration is encoded in the
// URL so a specific setup can be shared as a link").
// ---------------------------------------------------------------------------

test('the configuration round-trips through the URL hash', async ({ page, context }) => {
  await page.locator('#ex1-a').fill('transfer=1&to=dana');
  await page.selectOption('#oracle-mode', 'etm');
  await page.locator('#oracle-message').fill('shared=link');
  await page.selectOption('#tmg-mode', 'ct');
  await page.selectOption('#chk-order', 'eam');
  await page.selectOption('#chk-aead', 'no');

  const hash = await page.evaluate(() => location.hash);
  const params = new URLSearchParams(hash.slice(1));
  expect(params.get('a')).toBe('transfer=1&to=dana');
  expect(params.get('om')).toBe('etm');
  expect(params.get('omsg')).toBe('shared=link');
  expect(params.get('tm')).toBe('ct');
  expect(params.get('co')).toBe('eam');
  expect(params.get('ca')).toBe('no');

  // A fresh load of that link reproduces the same configuration, and re-runs the
  // auto-running exhibits against it.
  const shared = await context.newPage();
  shared.on('pageerror', (error) => pageErrors.push(String(error)));
  await shared.goto(`.${hash}`);
  await expect(shared.locator('#ex1-mte .card-body .badge').first()).toBeVisible();
  expect(await shared.locator('#ex1-a').inputValue()).toBe('transfer=1&to=dana');
  expect(await shared.locator('#oracle-mode').inputValue()).toBe('etm');
  expect(await shared.locator('#oracle-message').inputValue()).toBe('shared=link');
  expect(await shared.locator('#tmg-mode').inputValue()).toBe('ct');
  expect(await shared.locator('#chk-order').inputValue()).toBe('eam');
  // The checklist auto-ran on the restored answers: no AEAD + E&M is a risk.
  await expect(shared.locator('#chk-output .badge')).toHaveClass(/badge-danger/);
  await expect(shared.locator('#chk-output .badge')).toContainText('Encrypt-and-MAC');
  await shared.close();
});
