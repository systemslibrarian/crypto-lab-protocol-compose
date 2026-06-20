import './style.css';
import {
  type CryptoSuite,
  createSuite,
  sealAead,
  sealEAndM,
  sealEtM,
  sealMtE,
  toHex,
  utf8,
} from './compose';
import {
  createMtEPaddingOracle,
  etmRejectsTampering,
  recoverMtEPlaintext,
  tlsEvolutionNotes,
} from './attacks';
import { CRIME_ALPHABET, crimeRecover, randomSecret } from './crime';

let attackRunning = false;

const prefersReducedMotion =
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/** Show a printable rendering of a byte: ASCII char, or a dot for control/non-ASCII. */
function printableChar(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? escapeHtml(String.fromCharCode(byte)) : '·';
}

function shortHex(data: Uint8Array, max = 16): string {
  const hex = toHex(data);
  return data.length > max ? `${hex.slice(0, max * 2)}…` : hex;
}

function badge(kind: 'safe' | 'warn' | 'danger', label: string): string {
  const symbol = kind === 'safe' ? '✓' : kind === 'warn' ? '⚠' : '✗';
  const word = kind === 'safe' ? 'Safe' : kind === 'warn' ? 'Caution' : 'Risk';
  return `<span class="badge badge-${kind}"><span aria-hidden="true">${symbol}</span> <span class="sr-only">${word}: </span>${escapeHtml(label)}</span>`;
}

function wireThemeToggle(): void {
  const root = document.documentElement;
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) {
    return;
  }

  const setThemeUi = (theme: 'dark' | 'light'): void => {
    root.dataset.theme = theme;
    button.textContent = theme === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  };

  const initialTheme: 'dark' | 'light' = root.dataset.theme === 'light' ? 'light' : 'dark';
  setThemeUi(initialTheme);

  button.addEventListener('click', () => {
    const nextTheme: 'dark' | 'light' = root.dataset.theme === 'light' ? 'dark' : 'light';
    setThemeUi(nextTheme);
    localStorage.setItem('theme', nextTheme);
  });
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root element');
}

app.innerHTML = `
  <a class="skip-link" href="#main-content">Skip to main content</a>
  <div class="page">
    <header class="hero" role="banner">
      <button
        id="theme-toggle"
        type="button"
        class="theme-toggle"
        aria-label="Switch to light mode"
      >🌙</button>
      <h1>Protocol Composition Safety</h1>
      <p>
        Each primitive below — AES-CBC, HMAC-SHA-256, AES-256-GCM — is secure on its own.
        Watch what happens when you combine them in different orders.
      </p>
    </header>

    <main class="stack" id="main-content" tabindex="-1">
    <section class="panel intro" aria-labelledby="intro-title">
      <h2 id="intro-title">How to read this lab</h2>
      <p class="note">
        <strong>Threat model:</strong> the attacker can read every byte you send, tamper with
        ciphertexts in flight, and watch how the receiver reacts (accept / reject). They never see
        the key. The question each exhibit asks: <em>does this composition leak anything anyway?</em>
      </p>
      <ul class="legend" aria-label="Badge legend">
        <li>${badge('safe', 'no usable leak')}</li>
        <li>${badge('warn', 'leaks metadata')}</li>
        <li>${badge('danger', 'recovers plaintext')}</li>
      </ul>
    </section>

    <section class="panel" aria-labelledby="ex1-title">
      <h2 id="ex1-title">Exhibit 1 — The Four Orders, Side by Side</h2>
      <p class="note">
        The same message is sealed <strong>twice</strong> under each composition. Compare the two
        sends: anything that stays identical across sends is something an eavesdropper can exploit.
      </p>
      <label for="ex1-message">Message</label>
      <textarea id="ex1-message">transfer=2500&amp;to=alice</textarea>
      <button id="ex1-run" type="button">Seal it twice in every mode</button>
      <div class="three-grid">
        <article class="card" id="ex1-mte">
          <h3>MAC-then-Encrypt (MtE)</h3>
          <p class="note">MAC the plaintext, append the tag, then encrypt both together.</p>
          <div class="card-body"></div>
        </article>
        <article class="card" id="ex1-etm">
          <h3>Encrypt-then-MAC (EtM)</h3>
          <p class="note">Encrypt first, MAC the ciphertext, verify the tag before decrypting.</p>
          <div class="card-body"></div>
        </article>
        <article class="card" id="ex1-eam">
          <h3>Encrypt-and-MAC (E&amp;M)</h3>
          <p class="note">Encrypt the plaintext and MAC the plaintext separately.</p>
          <div class="card-body"></div>
        </article>
      </div>
      <article class="card" id="ex1-aead">
        <h3>AEAD (AES-256-GCM)</h3>
        <p class="note">Confidentiality and integrity from a single, purpose-built primitive.</p>
        <div class="card-body"></div>
      </article>
      <p class="takeaway">
        Same three primitives every time — only the <strong>order</strong> changes. Yet E&amp;M
        repeats its tag (it leaks when you resend a message), and MtE forces the receiver to decrypt
        before it can authenticate. That decrypt-first habit is the door Exhibit 2 walks through.
      </p>
    </section>

    <section class="panel" aria-labelledby="ex2-title">
      <h2 id="ex2-title">Exhibit 2 — The Padding Oracle, Live</h2>
      <p class="note">
        An attacker who can tamper with ciphertext and see only "padding ok / padding bad" can
        recover the entire plaintext — <strong>one byte at a time, with no key</strong>. MtE leaves
        that door open; EtM closes it. Switch modes and run it.
      </p>
      <label for="oracle-mode">Composition under attack</label>
      <select id="oracle-mode">
        <option value="mte">MtE — verifier decrypts before checking the MAC (vulnerable)</option>
        <option value="etm">EtM — verifier checks the MAC before decrypting (safe)</option>
      </select>
      <label for="oracle-message">Secret message to steal</label>
      <input id="oracle-message" value="pay=bob;amt=1337" maxlength="64" />
      <button id="oracle-run" type="button" aria-describedby="oracle-status">Run the attack</button>
      <p class="note">
        Deep dive into this attack on its own:
        <a href="https://systemslibrarian.github.io/crypto-lab-padding-oracle/" target="_blank" rel="noreferrer">crypto-lab-padding-oracle<span class="sr-only"> (opens in new tab)</span></a>
      </p>
      <div class="oracle-output">
        <div id="oracle-visual" class="hex" aria-hidden="true">Press “Run the attack” to begin.</div>
        <p id="oracle-status" class="status-line" role="status" aria-live="polite"></p>
      </div>
      <details class="explainer">
        <summary>Why does MtE leak? (the CBC mechanics)</summary>
        <p class="note">
          CBC decryption computes each plaintext block as
          <code>Pᵢ = D<sub>K</sub>(Cᵢ) ⊕ C<sub>ᵢ₋₁</sub></code>. The attacker can't touch
          <code>D<sub>K</sub>(Cᵢ)</code>, but they fully control the previous ciphertext block
          <code>C<sub>ᵢ₋₁</sub></code> — so flipping its bytes flips the matching bytes of
          <code>Pᵢ</code>. They tune the last byte until the decrypted block ends in valid padding
          (<code>0x01</code>). “Padding OK / bad” is the oracle, and from it
          <code>D<sub>K</sub>(Cᵢ)</code> — and thus the real plaintext — falls out byte by byte.
        </p>
        <svg class="cbc-diagram" viewBox="0 0 520 150" role="img"
             aria-label="CBC decryption: ciphertext block C sub i goes through AES decrypt, then is XORed with the previous ciphertext block C sub i minus 1, which the attacker controls, producing plaintext block P sub i.">
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="currentColor" />
            </marker>
          </defs>
          <g font-size="13" text-anchor="middle">
            <rect class="d-box" x="20" y="20" width="120" height="36" rx="6" />
            <text x="80" y="43">Cᵢ (ciphertext)</text>
            <rect class="d-box" x="20" y="90" width="120" height="36" rx="6" />
            <text x="80" y="113">AES decrypt (key)</text>
            <line x1="80" y1="56" x2="80" y2="88" stroke="currentColor" marker-end="url(#arrow)" />

            <circle class="d-xor" cx="290" cy="108" r="20" />
            <text x="290" y="113" font-size="18">⊕</text>
            <line x1="140" y1="108" x2="268" y2="108" stroke="currentColor" marker-end="url(#arrow)" />

            <rect class="d-attacker" x="200" y="18" width="180" height="40" rx="6" />
            <text x="290" y="34">Cᵢ₋₁ (prev block)</text>
            <text x="290" y="50" class="d-attacker-text">↑ attacker flips these bytes</text>
            <line x1="290" y1="58" x2="290" y2="86" stroke="currentColor" marker-end="url(#arrow)" />

            <rect class="d-out" x="410" y="90" width="90" height="36" rx="6" />
            <text x="455" y="113">Pᵢ</text>
            <line x1="310" y1="108" x2="408" y2="108" stroke="currentColor" marker-end="url(#arrow)" />
          </g>
        </svg>
      </details>
    </section>

    <section class="panel" aria-labelledby="ex3-title">
      <h2 id="ex3-title">Exhibit 3 — A Different Seam: Compress-then-Encrypt (CRIME)</h2>
      <p class="note">
        Same lesson, new seam. Compressing <em>before</em> encrypting leaks plaintext through the
        ciphertext's <strong>length</strong> — encryption hides content, not size. The attacker below
        never decrypts anything: it injects guesses next to a secret and watches the compressed size.
      </p>
      <div class="crime-secret">
        <span class="repeat-label">secret (the attacker cannot read this directly)</span>
        <code id="crime-secret">session=…</code>
      </div>
      <div class="btn-row">
        <button id="crime-run" type="button" aria-describedby="crime-status">Recover it using only length</button>
        <button id="crime-reset" type="button">New secret</button>
      </div>
      <div class="oracle-output">
        <div id="crime-visual" class="hex" aria-hidden="true"></div>
        <p id="crime-status" class="status-line" role="status" aria-live="polite"></p>
      </div>
      <p class="note">
        The same "each piece is fine, the seam is not" pattern also breaks
        <strong>hash-then-sign</strong> (length extension) and <strong>sign-then-encrypt</strong>
        (a signed plaintext can be peeled off and forwarded by someone else).
      </p>
    </section>

    <section class="panel" aria-labelledby="ex4-title">
      <h2 id="ex4-title">Exhibit 4 — How TLS Learned This Lesson</h2>
      <p class="note">Step through the record layer from TLS 1.0 to 1.3, or press play to watch it evolve.</p>
      <div class="tls-dots" id="tls-dots" aria-hidden="true"></div>
      <div class="btn-row">
        <button id="tls-prev" type="button" aria-label="Previous TLS version">Previous</button>
        <button id="tls-play" type="button" aria-pressed="false">Play walkthrough</button>
        <button id="tls-next" type="button" aria-label="Next TLS version">Next</button>
      </div>
      <article id="tls-card" class="card" role="region" aria-live="polite" aria-label="Current TLS version detail"></article>
    </section>

    <section class="panel" aria-labelledby="ex5-title">
      <h2 id="ex5-title">Exhibit 5 — Score Your Own Protocol</h2>
      <p class="note">Answer for a design you are reviewing and see where it lands.</p>
      <label for="chk-aead">Are you using AEAD (e.g. AES-GCM, ChaCha20-Poly1305)?</label>
      <select id="chk-aead">
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </select>
      <label for="chk-etm">If not AEAD, is the MAC verified before decryption?</label>
      <select id="chk-etm">
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </select>
      <label for="chk-order">What composition order?</label>
      <select id="chk-order">
        <option value="etm">Encrypt-then-MAC</option>
        <option value="mte">MAC-then-Encrypt</option>
        <option value="eam">Encrypt-and-MAC</option>
      </select>
      <button id="chk-run" type="button">Evaluate this design</button>
      <div id="chk-output" class="oracle-output" role="status" aria-live="polite"></div>
    </section>
    </main>

    <footer class="hero" role="contentinfo">
      <p>"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
    </footer>
  </div>
`;

wireThemeToggle();

const suitePromise = createSuite().catch((err) => {
  const banner = document.querySelector<HTMLElement>('.hero p');
  if (banner) {
    banner.textContent = 'WebCrypto is not available. This demo requires a secure context (HTTPS or localhost).';
    banner.style.color = 'var(--text)';
  }
  throw err;
});

// ---------------------------------------------------------------------------
// Exhibit 1 — seal the same message twice per mode, expose what repeats.
// ---------------------------------------------------------------------------

function repeatRow(label: string, a: Uint8Array, b: Uint8Array): string {
  return `<div class="repeat">
    <span class="repeat-label">${escapeHtml(label)}</span>
    <code>send 1: ${shortHex(a)}</code>
    <code>send 2: ${shortHex(b)}</code>
  </div>`;
}

function renderCardBody(card: HTMLElement | null, html: string): void {
  const body = card?.querySelector<HTMLElement>('.card-body');
  if (body) {
    body.innerHTML = html;
  }
}

async function runExhibit1(suite: CryptoSuite, message: string): Promise<void> {
  const [mteA, mteB, etmA, etmB, eamA, eamB, aeadA, aeadB] = await Promise.all([
    sealMtE(suite, message), sealMtE(suite, message),
    sealEtM(suite, message), sealEtM(suite, message),
    sealEAndM(suite, message), sealEAndM(suite, message),
    sealAead(suite, message), sealAead(suite, message),
  ]);

  renderCardBody(document.querySelector('#ex1-mte'), `
    <p class="attacker-view">Attacker sees: <code>iv + ciphertext</code> (the tag is sealed inside).</p>
    ${repeatRow('ciphertext', mteA.ciphertext, mteB.ciphertext)}
    ${badge('safe', 'ciphertext differs each send — no equality leak')}
    ${badge('danger', 'verifier must DECRYPT before it can check the tag → padding oracle')}
  `);

  const etmTagRepeats = toHex(etmA.tag) === toHex(etmB.tag);
  renderCardBody(document.querySelector('#ex1-etm'), `
    <p class="attacker-view">Attacker sees: <code>iv + ciphertext + tag</code>. Tag = HMAC(iv‖ciphertext).</p>
    ${repeatRow('tag', etmA.tag, etmB.tag)}
    ${etmTagRepeats
      ? badge('warn', 'tag repeated (unexpected)')
      : badge('safe', 'tag differs each send — no equality leak')}
    ${badge('safe', 'tag is checked BEFORE decryption → tampering rejected early')}
  `);

  const eamTagRepeats = toHex(eamA.tag) === toHex(eamB.tag);
  renderCardBody(document.querySelector('#ex1-eam'), `
    <p class="attacker-view">Attacker sees: <code>iv + ciphertext + tag</code>. Tag = HMAC(plaintext).</p>
    ${repeatRow('tag', eamA.tag, eamB.tag)}
    ${eamTagRepeats
      ? badge('warn', 'identical tag → reveals you re-sent the same message')
      : badge('safe', 'tag differs (unexpected)')}
    ${badge('danger', 'tag covers plaintext, so verifier still decrypts first')}
  `);

  const aeadTagRepeats = toHex(aeadA.tag) === toHex(aeadB.tag);
  renderCardBody(document.querySelector('#ex1-aead'), `
    <p class="attacker-view">Attacker sees: <code>nonce + ciphertext + tag</code>, all from one primitive.</p>
    ${repeatRow('tag', aeadA.tag, aeadB.tag)}
    ${aeadTagRepeats
      ? badge('warn', 'tag repeated (reused nonce?)')
      : badge('safe', 'everything differs each send — no equality leak')}
    ${badge('safe', 'authentication and decryption happen atomically')}
  `);
}

const ex1Run = document.querySelector<HTMLButtonElement>('#ex1-run');
const ex1Message = document.querySelector<HTMLTextAreaElement>('#ex1-message');
if (ex1Run && ex1Message) {
  ex1Run.addEventListener('click', async () => {
    ex1Run.disabled = true;
    try {
      const suite = await suitePromise;
      await runExhibit1(suite, ex1Message.value);
    } catch (e) {
      console.error('Exhibit 1 error:', e);
    } finally {
      ex1Run.disabled = false;
    }
  });
  ex1Run.click();
}

// ---------------------------------------------------------------------------
// Exhibit 2 — run the padding oracle and make the byte-by-byte leak visible.
// ---------------------------------------------------------------------------

const oracleRun = document.querySelector<HTMLButtonElement>('#oracle-run');
const oracleMode = document.querySelector<HTMLSelectElement>('#oracle-mode');
const oracleMessage = document.querySelector<HTMLInputElement>('#oracle-message');
const oracleVisual = document.querySelector<HTMLElement>('#oracle-visual');
const oracleStatus = document.querySelector<HTMLElement>('#oracle-status');

function renderRecovery(buf: (number | null)[], secretLen: number): string {
  let secret = '';
  for (let i = 0; i < secretLen; i += 1) {
    const b = buf[i];
    secret += b === null ? '<span class="pending">·</span>' : `<span class="recovered">${printableChar(b)}</span>`;
  }
  let extra = 0;
  for (let i = secretLen; i < buf.length; i += 1) {
    if (buf[i] !== null) extra += 1;
  }
  return `<div class="recovery">recovered message: <span class="recovery-text">${secret}</span></div>
    <div class="recovery-extra">+ ${extra} bytes of HMAC tag &amp; CBC padding (also peeled off)</div>`;
}

if (oracleRun && oracleMode && oracleMessage && oracleVisual && oracleStatus) {
  oracleRun.addEventListener('click', async () => {
    if (attackRunning) return;
    attackRunning = true;
    oracleRun.disabled = true;
    oracleStatus.className = 'status-line';
    try {
      const suite = await suitePromise;
      const mode = oracleMode.value;
      const msg = oracleMessage.value;

      if (!msg.trim()) {
        oracleVisual.textContent = '';
        oracleStatus.textContent = 'Enter a message before running the attack.';
        return;
      }

      if (mode === 'mte') {
        const secretLen = utf8(msg).length;
        const packet = await sealMtE(suite, msg);
        const oracle = createMtEPaddingOracle(suite);
        oracleStatus.textContent = 'Running padding-oracle attack against MtE…';
        oracleVisual.innerHTML = '';

        const result = await recoverMtEPlaintext(packet, oracle);
        const buf: (number | null)[] = new Array(result.recovered.length).fill(null);

        if (prefersReducedMotion) {
          for (const step of result.steps) {
            buf[step.blockIndex * 16 + step.byteIndex] = step.recoveredByte;
          }
          oracleVisual.innerHTML = renderRecovery(buf, secretLen);
        } else {
          for (const step of result.steps) {
            buf[step.blockIndex * 16 + step.byteIndex] = step.recoveredByte;
            oracleVisual.innerHTML = renderRecovery(buf, secretLen);
            await new Promise((resolve) => setTimeout(resolve, 12));
          }
        }

        oracleStatus.className = 'status-line verdict-danger';
        oracleStatus.textContent =
          `✗ MtE broken: recovered the full plaintext in ${result.queries} oracle queries — ` +
          `no key, just pass/fail padding signals. Decrypting before authenticating is the bug.`;
        return;
      }

      // EtM: tamper, then watch the MAC reject it before any decryption.
      const packet = await sealEtM(suite, msg);
      const blocked = await etmRejectsTampering(suite, packet);
      oracleVisual.innerHTML =
        `<div class="recovery">tampered packet → <span class="recovered">rejected at the MAC</span></div>
         <div class="recovery-extra">0 bytes leaked — decryption never ran, so there is nothing to query.</div>`;
      oracleStatus.className = blocked ? 'status-line verdict-safe' : 'status-line';
      oracleStatus.textContent = blocked
        ? '✓ EtM safe: the MAC covers the ciphertext and is checked first. The padding oracle has no surface to attack.'
        : 'Unexpected result: EtM did not reject tampering early.';
    } catch (e) {
      oracleStatus.className = 'status-line';
      oracleStatus.textContent = 'Error: could not run attack. See console for details.';
      console.error('Oracle attack error:', e);
    } finally {
      attackRunning = false;
      oracleRun.disabled = false;
    }
  });
}

// ---------------------------------------------------------------------------
// Exhibit 3 — CRIME: recover a secret from compressed length alone.
// ---------------------------------------------------------------------------

const crimeRun = document.querySelector<HTMLButtonElement>('#crime-run');
const crimeReset = document.querySelector<HTMLButtonElement>('#crime-reset');
const crimeSecretEl = document.querySelector<HTMLElement>('#crime-secret');
const crimeVisual = document.querySelector<HTMLElement>('#crime-visual');
const crimeStatus = document.querySelector<HTMLElement>('#crime-status');

let crimeRunning = false;
let crimeSecret = `session=${randomSecret(8)}`;

function renderCrimeSecret(): void {
  if (crimeSecretEl) {
    crimeSecretEl.textContent = crimeSecret;
  }
}
renderCrimeSecret();

function renderCrimeProgress(recovered: string): void {
  if (!crimeVisual) return;
  const target = crimeSecret.replace(/^session=/, '');
  let out = '';
  for (let i = 0; i < target.length; i += 1) {
    out += i < recovered.length
      ? `<span class="recovered">${escapeHtml(recovered[i])}</span>`
      : '<span class="pending">·</span>';
  }
  crimeVisual.innerHTML = `<div class="recovery">session=<span class="recovery-text">${out}</span></div>`;
}

if (crimeRun && crimeVisual && crimeStatus) {
  crimeRun.addEventListener('click', async () => {
    if (crimeRunning) return;
    crimeRunning = true;
    crimeRun.disabled = true;
    if (crimeReset) crimeReset.disabled = true;
    crimeStatus.className = 'status-line';
    try {
      if (typeof CompressionStream === 'undefined') {
        crimeStatus.textContent = 'This browser lacks CompressionStream, so this exhibit cannot run.';
        return;
      }
      const target = crimeSecret.replace(/^session=/, '');
      crimeStatus.textContent = 'Recovering the secret from compressed length only…';
      renderCrimeProgress('');
      const result = await crimeRecover(target, CRIME_ALPHABET, async (step) => {
        renderCrimeProgress(step.recovered);
        if (!prefersReducedMotion) {
          await new Promise((resolve) => setTimeout(resolve, 90));
        }
      });
      renderCrimeProgress(result.recovered);
      const success = result.recovered === target;
      crimeStatus.className = success ? 'status-line verdict-danger' : 'status-line';
      crimeStatus.textContent = success
        ? `✗ Recovered the full secret in ${result.queries} length measurements — no decryption, just compressed size.`
        : 'Recovery was incomplete (compression noise). Try “New secret”.';
    } catch (e) {
      crimeStatus.className = 'status-line';
      crimeStatus.textContent = 'Error: could not run the CRIME demo. See console for details.';
      console.error('CRIME demo error:', e);
    } finally {
      crimeRunning = false;
      crimeRun.disabled = false;
      if (crimeReset) crimeReset.disabled = false;
    }
  });
}

if (crimeReset) {
  crimeReset.addEventListener('click', () => {
    if (crimeRunning) return;
    crimeSecret = `session=${randomSecret(8)}`;
    renderCrimeSecret();
    if (crimeVisual) crimeVisual.innerHTML = '';
    if (crimeStatus) {
      crimeStatus.className = 'status-line';
      crimeStatus.textContent = '';
    }
  });
}

// ---------------------------------------------------------------------------
// Exhibit 4 — TLS evolution walkthrough.
// ---------------------------------------------------------------------------

const tlsData = tlsEvolutionNotes();
let tlsIndex = 0;
const tlsCard = document.querySelector<HTMLElement>('#tls-card');
const tlsDots = document.querySelector<HTMLElement>('#tls-dots');
const tlsPrev = document.querySelector<HTMLButtonElement>('#tls-prev');
const tlsPlay = document.querySelector<HTMLButtonElement>('#tls-play');
const tlsNext = document.querySelector<HTMLButtonElement>('#tls-next');
let tlsTimer: number | null = null;

const safetyLabel: Record<'danger' | 'warn' | 'safe', string> = {
  danger: 'Vulnerable composition',
  warn: 'Residual risk',
  safe: 'Safe by design',
};

const renderTls = (): void => {
  if (tlsCard) {
    const point = tlsData[tlsIndex];
    tlsCard.innerHTML = `
      <div class="tls-head">
        <h3>${escapeHtml(point.version)}</h3>
        ${badge(point.safety, safetyLabel[point.safety])}
      </div>
      <p><strong>Composition:</strong> ${escapeHtml(point.composition)}</p>
      <p><strong>Observed outcome:</strong> ${escapeHtml(point.failureOrWin)}</p>
      <p><strong>Lesson:</strong> ${escapeHtml(point.lesson)}</p>
    `;
  }
  if (tlsDots) {
    tlsDots.innerHTML = tlsData
      .map((p, i) => `<span class="tls-dot tls-dot-${p.safety}${i === tlsIndex ? ' tls-dot-active' : ''}"></span>`)
      .join('');
  }
};
renderTls();

if (tlsPrev) {
  tlsPrev.addEventListener('click', () => {
    tlsIndex = (tlsIndex - 1 + tlsData.length) % tlsData.length;
    renderTls();
  });
}

if (tlsNext) {
  tlsNext.addEventListener('click', () => {
    tlsIndex = (tlsIndex + 1) % tlsData.length;
    renderTls();
  });
}

if (tlsPlay) {
  tlsPlay.addEventListener('click', () => {
    if (tlsTimer !== null) {
      window.clearInterval(tlsTimer);
      tlsTimer = null;
      tlsPlay.textContent = 'Play walkthrough';
      tlsPlay.setAttribute('aria-pressed', 'false');
      tlsCard?.setAttribute('aria-live', 'polite');
      return;
    }
    tlsPlay.textContent = 'Pause walkthrough';
    tlsPlay.setAttribute('aria-pressed', 'true');
    // Avoid announcing every auto-advance; manual prev/next still announce.
    tlsCard?.setAttribute('aria-live', 'off');
    tlsTimer = window.setInterval(() => {
      tlsIndex = (tlsIndex + 1) % tlsData.length;
      renderTls();
    }, 1800);
  });
}

window.addEventListener('beforeunload', () => {
  if (tlsTimer !== null) {
    window.clearInterval(tlsTimer);
  }
});

// ---------------------------------------------------------------------------
// Exhibit 5 — protocol safety checklist.
// ---------------------------------------------------------------------------

const chkRun = document.querySelector<HTMLButtonElement>('#chk-run');
const chkAead = document.querySelector<HTMLSelectElement>('#chk-aead');
const chkEtm = document.querySelector<HTMLSelectElement>('#chk-etm');
const chkOrder = document.querySelector<HTMLSelectElement>('#chk-order');
const chkOutput = document.querySelector<HTMLElement>('#chk-output');

if (chkRun && chkAead && chkEtm && chkOrder && chkOutput) {
  chkRun.addEventListener('click', () => {
    const usesAead = chkAead.value === 'yes';
    const usesEtm = chkEtm.value === 'yes';
    const order = chkOrder.value;

    let kind: 'safe' | 'warn' | 'danger';
    let verdict: string;
    let reason: string;

    if (usesAead) {
      kind = 'safe';
      verdict = 'Safe by design';
      reason = 'A single AEAD primitive authenticates and decrypts together, so composition ordering simply cannot go wrong here.';
    } else if (order === 'etm' && usesEtm) {
      kind = 'warn';
      verdict = 'Acceptable with care';
      reason = 'Encrypt-then-MAC with the MAC verified before decryption is the safe non-AEAD order — but you must also use constant-time tag comparison and a separate MAC key. Prefer AEAD if you can.';
    } else if (order === 'etm' && !usesEtm) {
      kind = 'danger';
      verdict = 'Order claimed, but not enforced';
      reason = 'You selected Encrypt-then-MAC but said the MAC is not verified before decryption. That reintroduces the decrypt-first oracle — verify the tag first or the order buys you nothing.';
    } else if (order === 'eam') {
      kind = 'danger';
      verdict = 'Vulnerable — Encrypt-and-MAC';
      reason = 'MACing the plaintext leaks message equality (Exhibit 1) and still forces decrypt-before-verify. Not recommended for new designs.';
    } else {
      kind = 'danger';
      verdict = 'Vulnerable — MAC-then-Encrypt';
      reason = 'Decrypting before checking the MAC exposes a padding-oracle surface (Exhibit 2). This is the order TLS spent two decades removing.';
    }

    chkOutput.innerHTML = `
      <div class="verdict-head">${badge(kind, verdict)}</div>
      <p class="note">${reason}</p>
    `;
  });
  chkRun.click();
}
