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
  type OracleStep,
  createMtEPaddingOracle,
  etmRejectsTampering,
  recoverMtEPlaintext,
  tlsEvolutionNotes,
} from './attacks';
import { CRIME_ALPHABET, crimeRecover, randomSecret } from './crime';
import {
  type CompareFn,
  constantTimeEqual,
  naiveEqual,
  randomTag,
  recoverViaTiming,
} from './timing';

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

/**
 * Plain-language gloss for a jargon term. Renders the term with a dotted
 * underline and a native tooltip (title), plus a screen-reader-only expansion so
 * the definition is available to AT users too — the newcomer on-ramp the
 * pedagogy review asked for, without cluttering the prose for experts.
 */
function gloss(term: string, definition: string): string {
  return `<span class="gloss" tabindex="0" role="note" title="${escapeHtml(definition)}" aria-label="${escapeHtml(term)}: ${escapeHtml(definition)}">${escapeHtml(term)}</span>`;
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
    <header class="cl-hero" role="banner">
      <button
        id="theme-toggle"
        type="button"
        class="theme-toggle"
        aria-label="Switch to light mode"
      >🌙</button>
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">Protocol Composition</h1>
        <p class="cl-hero-sub">MtE · EtM · E&amp;M · AEAD</p>
        <p class="cl-hero-desc">
          Seal messages under each way of combining AES-CBC, HMAC-SHA-256, and AES-GCM,
          then watch padding-oracle, timing, and CRIME attacks break the unsafe orderings.
        </p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">
          Every primitive here is individually secure, yet the wrong composition
          order sank real systems — padding oracles, Lucky Thirteen, and CRIME all
          exploited it. Getting the order right is what modern TLS spent a decade fixing.
        </p>
      </aside>
    </header>

    <main class="stack" id="main-content" tabindex="-1">
    <section class="panel intro" aria-labelledby="intro-title">
      <h2 id="intro-title">How to read this lab</h2>
      <p class="note">
        <strong>Threat model:</strong> the attacker can read every byte you send, tamper with
        ciphertexts in flight, and watch how the receiver reacts (accept / reject). They never see
        the key. The question each exhibit asks: <em>does this composition leak anything anyway?</em>
      </p>
      <p class="note new-here">
        <strong>New to this?</strong> A few words used throughout — hover or focus the dotted terms
        for a one-line gloss. A ${gloss('MAC', 'message authentication code: a keyed fingerprint that proves a message was not altered')}
        is a keyed fingerprint that proves a message was not altered. An
        ${gloss('IV', 'initialization vector: a fresh random value so identical messages encrypt differently')} or
        ${gloss('nonce', 'number used once: a fresh value so identical messages encrypt differently')} is a
        fresh random value so identical messages encrypt differently. ${gloss('AEAD', 'authenticated encryption with associated data: one primitive that encrypts and authenticates together')}
        is one primitive that encrypts and authenticates together.
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
        Seal <strong>two</strong> messages under each composition and compare their outputs. Try it
        with <strong>different</strong> messages, then make them <strong>identical</strong>: anything
        that turns equal only when the plaintexts match is an equality leak an eavesdropper can read.
      </p>
      <div class="msg-pair">
        <div>
          <label for="ex1-a">Message A</label>
          <textarea id="ex1-a">transfer=2500&amp;to=alice</textarea>
        </div>
        <div>
          <label for="ex1-b">Message B</label>
          <textarea id="ex1-b">transfer=2500&amp;to=bob</textarea>
        </div>
      </div>
      <div class="btn-row">
        <button id="ex1-run" type="button">Seal both in every mode</button>
        <button id="ex1-match" type="button">Make B identical to A</button>
      </div>
      <p id="ex1-hint" class="note" role="status" aria-live="polite"></p>
      <div class="three-grid">
        <article class="card" id="ex1-mte">
          <h3>MAC-then-Encrypt (MtE)</h3>
          <p class="note">${gloss('MAC', 'message authentication code: a keyed fingerprint that proves a message was not altered')} the plaintext, append the tag, then encrypt both together.</p>
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
        <h3>${gloss('AEAD', 'authenticated encryption with associated data: one primitive that encrypts and authenticates together')} (AES-256-GCM)</h3>
        <p class="note">Confidentiality and integrity from a single, purpose-built primitive.</p>
        <div class="card-body"></div>
        <p class="note aead-caveat">
          <strong>Not invincible — it moves the footgun.</strong> AEAD removes the composition seam,
          but AES-GCM keeps <em>one</em> of its own: reuse a nonce with the same key and confidentiality
          <em>and</em> integrity collapse. Safe composition still needs a nonce discipline. See
          <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/" target="_blank" rel="noreferrer">crypto-lab-nonce-guard<span class="sr-only"> (opens in new tab)</span></a>.
        </p>
      </article>
      <p class="takeaway">
        Same three primitives every time — only the <strong>order</strong> changes. Yet when A and B
        are identical, E&amp;M hands back the <strong>same tag</strong> (its tag is HMAC of the
        plaintext, so equal messages leak), while EtM and AEAD stay different because a fresh random
        IV/nonce feeds every tag. MtE, meanwhile, forces the receiver to decrypt before it can
        authenticate — the decrypt-first door Exhibit 2 walks through.
      </p>
    </section>

    <section class="panel spectrum" aria-labelledby="spectrum-title">
      <h2 id="spectrum-title">You are here: the four orders as a spectrum</h2>
      <p class="note">
        The next four exhibits each attack one of these compositions. Read them against this map so
        you can predict which order a given attack targets <em>before</em> you run it:
      </p>
      <ol class="spectrum-list">
        <li><span class="spectrum-tag spectrum-danger">MtE</span> decrypt-first — <strong>worst</strong>: opens a padding oracle (Exhibit 2).</li>
        <li><span class="spectrum-tag spectrum-warn">E&amp;M</span> leaks message <strong>equality</strong> (Exhibit 1, the tags that snapped equal).</li>
        <li><span class="spectrum-tag spectrum-safe">EtM</span> <strong>safe with care</strong> — but only if the tag check is constant-time (Exhibit 3).</li>
        <li><span class="spectrum-tag spectrum-safe">AEAD</span> <strong>safe by design</strong> — one primitive, no seam to get wrong (with one caveat below).</li>
      </ol>
      <p class="note">
        A cross-cutting reminder: even the right order fails at a different seam — timing (Exhibit 3)
        and compression (Exhibit 4) leak without touching the composition at all.
      </p>
    </section>

    <section class="panel" aria-labelledby="ex2-title">
      <h2 id="ex2-title">Exhibit 2 — The Padding Oracle, Live</h2>
      <p class="note">
        An attacker who can tamper with ciphertext and see only "padding ok / padding bad" — any
        such ${gloss('padding oracle', 'any yes/no signal about whether decrypted padding was valid')} — can
        recover the entire plaintext <strong>one byte at a time, with no key</strong>. MtE leaves
        that door open; EtM closes it. Switch modes and run it, then watch the diagram below play the
        attack in step with the recovery.
      </p>
      <label for="oracle-mode">Composition under attack</label>
      <select id="oracle-mode">
        <option value="mte">MtE — verifier decrypts before checking the MAC (vulnerable)</option>
        <option value="etm">EtM — verifier checks the MAC before decrypting (safe)</option>
      </select>
      <label for="oracle-message">Secret message to steal</label>
      <input id="oracle-message" value="pay=bob;amt=1337" maxlength="64" />
      <button id="oracle-run" type="button" aria-describedby="oracle-status">Run the attack</button>

      <figure class="oracle-mech" id="oracle-mech" aria-hidden="true">
        <figcaption class="oracle-mech-cap">
          Live mechanism — <strong>one CBC block (16 bytes)</strong>. The attacker sweeps
          <code>0x00…0xFF</code> in the highlighted byte of the block they control; the instant
          padding checks out, the matching plaintext byte is known and flips green.
        </figcaption>
        <div class="mech-row">
          <span class="mech-label">Cᵢ₋₁ — attacker-controlled block</span>
          <div class="mech-track" id="mech-cprev"></div>
        </div>
        <div class="mech-xor" aria-hidden="true">↓ AES-decrypt(Cᵢ) ⊕ this block ↓</div>
        <div class="mech-row">
          <span class="mech-label">Pᵢ — recovered plaintext block</span>
          <div class="mech-track" id="mech-plain"></div>
        </div>
      </figure>

      <p class="note">
        Deep dive into this attack on its own:
        <a href="https://systemslibrarian.github.io/crypto-lab-padding-oracle/" target="_blank" rel="noreferrer">crypto-lab-padding-oracle<span class="sr-only"> (opens in new tab)</span></a>
      </p>
      <div class="oracle-output">
        <div id="oracle-visual" class="hex" aria-hidden="true">Press “Run the attack” to begin.</div>
        <p id="oracle-counter" class="query-counter" aria-hidden="true"></p>
        <p id="oracle-status" class="status-line" role="status" aria-live="polite"></p>
      </div>
      <details class="explainer">
        <summary>Go deeper: the CBC algebra behind that animation</summary>
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
      <h2 id="ex3-title">Exhibit 3 — The Clock Never Lies: Timing Side-Channels</h2>
      <p class="note">
        Even Encrypt-then-MAC breaks if the tag check itself leaks. A comparison that
        <strong>returns as soon as it hits a wrong byte</strong> runs longer the more leading bytes
        are correct — so the time a rejection takes reveals how much of a forged tag is right, and the
        whole tag falls out one byte at a time. That seam is <strong>Lucky Thirteen</strong>. The
        attacker below never reads the tag; it only watches how long the compare runs.
      </p>
      <label for="tmg-mode">Tag comparison under attack</label>
      <select id="tmg-mode">
        <option value="naive">Naive compare — bails at the first wrong byte (vulnerable)</option>
        <option value="ct">Constant-time compare — always scans every byte (safe)</option>
      </select>
      <div class="crime-secret">
        <span class="repeat-label">secret tag (the attacker cannot read this directly)</span>
        <code id="tmg-secret"></code>
      </div>
      <button id="tmg-run" type="button" aria-describedby="tmg-status">Recover the tag using only timing</button>
      <p class="note tmg-legend">
        <strong>Bar height = elapsed time = how many bytes the compare inspected before giving up.</strong>
        For each position the wrong guesses stop at the same short height; the one correct guess makes
        the compare run one byte further, so its bar edges taller — and that taller bar <em>is</em> the leak.
      </p>
      <div class="oracle-output">
        <div id="tmg-visual" class="hex" aria-hidden="true"></div>
        <p id="tmg-counter" class="query-counter" aria-hidden="true"></p>
        <p id="tmg-status" class="status-line" role="status" aria-live="polite"></p>
      </div>
      <p class="note">
        Timing leaks in depth:
        <a href="https://systemslibrarian.github.io/crypto-lab-timing-oracle/" target="_blank" rel="noreferrer">crypto-lab-timing-oracle<span class="sr-only"> (opens in new tab)</span></a>
      </p>
      <details class="explainer">
        <summary>Why does early-exit leak — and how does constant-time close it?</summary>
        <p class="note">
          A byte-by-byte compare that <code>return</code>s on the first mismatch runs in time
          proportional to the length of the correct prefix. Measure that time across many guesses and
          the correct next byte is the one whose comparison runs one step longer. The fix never
          branches on the secret: it ORs together every byte difference and always scans the whole
          tag, so the running time is identical whatever you feed it.
        </p>
        <pre class="code-block"><code>// leaks: stops early, time ∝ correct prefix length
for (let i = 0; i &lt; tag.length; i++)
  if (a[i] !== tag[i]) return false;   // ← the timing tell
return true;

// safe: constant work, no secret-dependent branch
let diff = 0;
for (let i = 0; i &lt; tag.length; i++) diff |= a[i] ^ tag[i];
return diff === 0;</code></pre>
      </details>
    </section>

    <section class="panel" aria-labelledby="ex4-title">
      <h2 id="ex4-title">Exhibit 4 — A Different Seam: Compress-then-Encrypt (CRIME)</h2>
      <p class="note">
        Same lesson, new seam. Compressing <em>before</em> encrypting leaks plaintext through the
        ciphertext's <strong>length</strong> — encryption hides content, not size. The attacker below
        never decrypts anything: it injects guesses next to a secret and watches the compressed size.
      </p>
      <p class="note">
        <strong>How the length leaks:</strong> the attacker gets one request that reflects <em>both</em>
        the secret and their own guess into the same compressed blob. DEFLATE replaces any repeated run
        with a short back-reference. When the guess <em>matches</em> the secret, the two lines share a
        longer run, so DEFLATE points back further and the output is a byte or two <strong>shorter</strong>
        — the correct next character is simply the one whose blob compresses smallest.
      </p>
      <div class="crime-reflect" aria-hidden="true">
        <span class="repeat-label">what the attacker's one request reflects (guess sits next to the secret)</span>
        <div class="crime-line"><span class="crime-fixed">Cookie: session=</span><span class="crime-secret-run" id="crime-secret-run">········</span></div>
        <div class="crime-line"><span class="crime-fixed">X-Probe: session=</span><span class="crime-guess-run" id="crime-guess-run">········</span></div>
        <div class="crime-sizebar" id="crime-sizebar"></div>
      </div>
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
        <p id="crime-counter" class="query-counter" aria-hidden="true"></p>
        <p id="crime-status" class="status-line" role="status" aria-live="polite"></p>
      </div>
      <p class="note">
        <strong>If a run ends "incomplete":</strong> that is the attack's real texture, not the demo
        failing. Two different characters sometimes compress to the same size (compression noise), so a
        greedy single pass can stall. Real CRIME beats this by <em>repeating and padding</em> the guess
        so the length gap is unambiguous, then retrying — press <strong>New secret</strong> to draw a
        cleaner one and watch it complete.
      </p>
      <p class="note">
        The same "each piece is fine, the seam is not" pattern also breaks
        <strong>hash-then-sign</strong> (length extension) and <strong>sign-then-encrypt</strong>
        (a signed plaintext can be peeled off and forwarded by someone else).
      </p>
    </section>

    <section class="panel" aria-labelledby="ex5-title">
      <h2 id="ex5-title">Exhibit 5 — How TLS Learned This Lesson</h2>
      <p class="note">Step through the record layer from TLS 1.0 to 1.3, or press play to watch it evolve.</p>
      <div class="tls-dots" id="tls-dots" aria-hidden="true"></div>
      <div class="btn-row">
        <button id="tls-prev" type="button" aria-label="Previous TLS version">Previous</button>
        <button id="tls-play" type="button" aria-pressed="false">Play walkthrough</button>
        <button id="tls-next" type="button" aria-label="Next TLS version">Next</button>
      </div>
      <article id="tls-card" class="card" role="region" aria-live="polite" aria-label="Current TLS version detail"></article>
    </section>

    <section class="panel" aria-labelledby="ex6-title">
      <h2 id="ex6-title">Exhibit 6 — Score Your Own Protocol</h2>
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
      <p>Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-padding-oracle/">crypto-lab-padding-oracle</a>,
        <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/">crypto-lab-aes-modes</a>,
        <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/">crypto-lab-nonce-guard</a>,
        <a href="https://systemslibrarian.github.io/crypto-lab-timing-oracle/">crypto-lab-timing-oracle</a>,
        <a href="https://systemslibrarian.github.io/crypto-lab-mac-race/">crypto-lab-mac-race</a></p>
      <p>"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
    </footer>
  </div>
`;

wireThemeToggle();

// ---------------------------------------------------------------------------
// Shareable deep-link state. Every persisted control maps to one short query
// key in the URL hash, so an instructor can link to a specific configuration.
// ---------------------------------------------------------------------------

const STATE_FIELDS: ReadonlyArray<readonly [key: string, selector: string]> = [
  ['a', '#ex1-a'],
  ['b', '#ex1-b'],
  ['om', '#oracle-mode'],
  ['omsg', '#oracle-message'],
  ['tm', '#tmg-mode'],
  ['ca', '#chk-aead'],
  ['ce', '#chk-etm'],
  ['co', '#chk-order'],
];

let applyingState = false;

function writeState(): void {
  if (applyingState) {
    return;
  }
  const params = new URLSearchParams();
  for (const [key, selector] of STATE_FIELDS) {
    const el = document.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(selector);
    if (el && el.value !== '') {
      params.set(key, el.value);
    }
  }
  const query = params.toString();
  history.replaceState(null, '', query ? `#${query}` : location.pathname + location.search);
}

function applyStateFromUrl(): void {
  const params = new URLSearchParams(location.hash.slice(1));
  if ([...params.keys()].length === 0) {
    return;
  }
  applyingState = true;
  for (const [key, selector] of STATE_FIELDS) {
    if (!params.has(key)) {
      continue;
    }
    const el = document.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(selector);
    if (el) {
      el.value = params.get(key) ?? '';
    }
  }
  applyingState = false;
}

// Keep the URL fresh as controls change, so the address bar is always shareable.
for (const [, selector] of STATE_FIELDS) {
  const el = document.querySelector<HTMLElement>(selector);
  el?.addEventListener(el instanceof HTMLSelectElement ? 'change' : 'input', writeState);
}

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
  const match = toHex(a) === toHex(b);
  return `<div class="repeat${match ? ' repeat-match' : ''}">
    <span class="repeat-label">${escapeHtml(label)}${match ? ' — identical across A and B' : ''}</span>
    <code>msg A: ${shortHex(a)}</code>
    <code>msg B: ${shortHex(b)}</code>
  </div>`;
}

function renderCardBody(card: HTMLElement | null, html: string): void {
  const body = card?.querySelector<HTMLElement>('.card-body');
  if (body) {
    body.innerHTML = html;
  }
}

async function runExhibit1(suite: CryptoSuite, messageA: string, messageB: string): Promise<void> {
  const [mteA, mteB, etmA, etmB, eamA, eamB, aeadA, aeadB] = await Promise.all([
    sealMtE(suite, messageA), sealMtE(suite, messageB),
    sealEtM(suite, messageA), sealEtM(suite, messageB),
    sealEAndM(suite, messageA), sealEAndM(suite, messageB),
    sealAead(suite, messageA), sealAead(suite, messageB),
  ]);

  const sameMessage = messageA === messageB;
  const equalHint = sameMessage
    ? 'A and B are identical — watch which mode gives it away.'
    : 'A and B differ. Try “Make B identical to A”.';

  renderCardBody(document.querySelector('#ex1-mte'), `
    <p class="attacker-view">Attacker sees: <code>iv + ciphertext</code> (the tag is sealed inside).</p>
    ${repeatRow('ciphertext', mteA.ciphertext, mteB.ciphertext)}
    ${badge('safe', 'ciphertext differs even for equal messages — no equality leak')}
    ${badge('danger', 'verifier must DECRYPT before it can check the tag → padding oracle')}
  `);

  const etmTagRepeats = toHex(etmA.tag) === toHex(etmB.tag);
  renderCardBody(document.querySelector('#ex1-etm'), `
    <p class="attacker-view">Attacker sees: <code>iv + ciphertext + tag</code>. Tag = ${gloss('HMAC', 'a MAC built from a hash (here SHA-256): a keyed fingerprint over its input')}(iv‖ciphertext) — the tag is a fingerprint of the <em>ciphertext</em>, not the plaintext.</p>
    ${repeatRow('tag', etmA.tag, etmB.tag)}
    ${etmTagRepeats
      ? badge('warn', 'tag repeated (unexpected)')
      : badge('safe', 'tag differs even for equal messages — the random IV feeds it')}
    ${badge('safe', 'tag is checked BEFORE decryption → tampering rejected early')}
  `);

  const eamTagRepeats = toHex(eamA.tag) === toHex(eamB.tag);
  renderCardBody(document.querySelector('#ex1-eam'), `
    <p class="attacker-view">Attacker sees: <code>iv + ciphertext + tag</code>. Tag = ${gloss('HMAC', 'a MAC built from a hash (here SHA-256): a keyed fingerprint over its input')}(plaintext) — equal plaintexts give the <em>same</em> tag.</p>
    ${repeatRow('tag', eamA.tag, eamB.tag)}
    ${eamTagRepeats
      ? badge('danger', 'identical tag → attacker learns A and B are the same message')
      : badge('safe', 'different messages → different tags (send equal ones to leak)')}
    ${badge('danger', 'tag covers plaintext, so verifier still decrypts first')}
  `);

  const aeadTagRepeats = toHex(aeadA.tag) === toHex(aeadB.tag);
  renderCardBody(document.querySelector('#ex1-aead'), `
    <p class="attacker-view">Attacker sees: <code>${gloss('nonce', 'number used once: a fresh value so identical messages encrypt differently')} + ciphertext + tag</code>, all from one primitive.</p>
    ${repeatRow('tag', aeadA.tag, aeadB.tag)}
    ${aeadTagRepeats
      ? badge('warn', 'tag repeated (reused nonce?)')
      : badge('safe', 'everything differs even for equal messages — no equality leak')}
    ${badge('safe', 'authentication and decryption happen atomically')}
  `);

  const hint = document.querySelector<HTMLElement>('#ex1-hint');
  if (hint) {
    hint.textContent = equalHint;
  }
}

const ex1Run = document.querySelector<HTMLButtonElement>('#ex1-run');
const ex1Match = document.querySelector<HTMLButtonElement>('#ex1-match');
const ex1MessageA = document.querySelector<HTMLTextAreaElement>('#ex1-a');
const ex1MessageB = document.querySelector<HTMLTextAreaElement>('#ex1-b');
if (ex1Run && ex1MessageA && ex1MessageB) {
  ex1Run.addEventListener('click', async () => {
    ex1Run.disabled = true;
    writeState();
    try {
      const suite = await suitePromise;
      await runExhibit1(suite, ex1MessageA.value, ex1MessageB.value);
    } catch (e) {
      console.error('Exhibit 1 error:', e);
    } finally {
      ex1Run.disabled = false;
    }
  });
  if (ex1Match) {
    ex1Match.addEventListener('click', () => {
      ex1MessageB.value = ex1MessageA.value;
      ex1Run.click();
    });
  }
}

// ---------------------------------------------------------------------------
// Exhibit 2 — run the padding oracle and make the byte-by-byte leak visible.
// ---------------------------------------------------------------------------

const oracleRun = document.querySelector<HTMLButtonElement>('#oracle-run');
const oracleMode = document.querySelector<HTMLSelectElement>('#oracle-mode');
const oracleMessage = document.querySelector<HTMLInputElement>('#oracle-message');
const oracleVisual = document.querySelector<HTMLElement>('#oracle-visual');
const oracleCounter = document.querySelector<HTMLElement>('#oracle-counter');
const oracleStatus = document.querySelector<HTMLElement>('#oracle-status');
const oracleMech = document.querySelector<HTMLElement>('#oracle-mech');
const mechCprev = document.querySelector<HTMLElement>('#mech-cprev');
const mechPlain = document.querySelector<HTMLElement>('#mech-plain');

/** Render the 16-byte C(i-1) and P(i) tracks of the live mechanism diagram. */
function initMechBlock(): void {
  if (mechCprev) {
    mechCprev.innerHTML = Array.from({ length: 16 }, () =>
      `<span class="mech-byte" role="presentation">··</span>`,
    ).join('');
  }
  if (mechPlain) {
    mechPlain.innerHTML = Array.from({ length: 16 }, () =>
      `<span class="mech-byte mech-pending">·</span>`,
    ).join('');
  }
}

/**
 * Animate one recovered byte: sweep the attacker's controlled byte of C(i-1)
 * (0x00..0xFF, sampled) while it is highlighted, then settle on the value that
 * fired "padding OK" and flip the matching plaintext byte green. This binds the
 * running attack to the diagram so the mechanism plays alongside the recovery.
 */
async function animateMechByte(
  byteIndex: number,
  guess: number,
  plainByte: number,
  animate: boolean,
): Promise<void> {
  const cprevCells = mechCprev?.children;
  const plainCells = mechPlain?.children;
  const cprevCell = cprevCells?.[byteIndex] as HTMLElement | undefined;
  const plainCell = plainCells?.[byteIndex] as HTMLElement | undefined;
  if (!cprevCell || !plainCell) return;

  // Clear any prior sweep highlight.
  for (const c of Array.from(cprevCells ?? [])) (c as HTMLElement).classList.remove('mech-sweeping');

  const hex = (n: number) => n.toString(16).padStart(2, '0');
  const glyph = plainByte >= 0x20 && plainByte <= 0x7e ? String.fromCharCode(plainByte) : '·';

  if (animate) {
    cprevCell.classList.add('mech-sweeping');
    // Sample the 0x00..0xFF sweep so it reads as "trying every value".
    for (let v = 0; v <= 0xff; v += 0x22) {
      cprevCell.textContent = hex(v);
      await new Promise((resolve) => setTimeout(resolve, 8));
    }
    cprevCell.classList.remove('mech-sweeping');
  }
  cprevCell.textContent = hex(guess);
  cprevCell.classList.add('mech-locked');
  plainCell.textContent = glyph;
  plainCell.classList.remove('mech-pending');
  plainCell.classList.add('mech-hit');
}

/**
 * Freeze the mechanism diagram on one specific CBC block's recovered bytes.
 * Called at the end of the run to settle on block 0 — the readable message
 * block — rather than the trailing tag/padding block full of non-printables.
 */
function freezeMechBlock(steps: OracleStep[], blockIndex: number): void {
  initMechBlock();
  for (const step of steps) {
    if (step.blockIndex === blockIndex) {
      void animateMechByte(step.byteIndex, step.guess, step.recoveredByte, false);
    }
  }
}

function renderCounter(el: HTMLElement | null, count: number, unit: string): void {
  if (el) {
    el.innerHTML = `<span class="counter-num">${count.toLocaleString()}</span> ${escapeHtml(unit)}`;
  }
}

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
    writeState();
    try {
      const suite = await suitePromise;
      const mode = oracleMode.value;
      const msg = oracleMessage.value;

      if (oracleCounter) oracleCounter.innerHTML = '';

      if (!msg.trim()) {
        oracleVisual.textContent = '';
        oracleStatus.textContent = 'Enter a message before running the attack.';
        return;
      }

      if (oracleMech) oracleMech.classList.remove('mech-idle');

      if (mode === 'mte') {
        const secretLen = utf8(msg).length;
        const packet = await sealMtE(suite, msg);
        const oracle = createMtEPaddingOracle(suite);
        oracleStatus.textContent = 'Running padding-oracle attack against MtE…';
        oracleVisual.innerHTML = '';
        initMechBlock();

        const result = await recoverMtEPlaintext(packet, oracle);
        const buf: (number | null)[] = new Array(result.recovered.length).fill(null);
        let shownBlock = -1;

        if (prefersReducedMotion) {
          for (const step of result.steps) {
            buf[step.blockIndex * 16 + step.byteIndex] = step.recoveredByte;
          }
          oracleVisual.innerHTML = renderRecovery(buf, secretLen);
          renderCounter(oracleCounter, result.queries, 'oracle queries');
        } else {
          for (const step of result.steps) {
            // A new CBC block is now under attack: reset the single-block diagram.
            if (step.blockIndex !== shownBlock) {
              shownBlock = step.blockIndex;
              initMechBlock();
            }
            buf[step.blockIndex * 16 + step.byteIndex] = step.recoveredByte;
            await animateMechByte(step.byteIndex, step.guess, step.recoveredByte, true);
            oracleVisual.innerHTML = renderRecovery(buf, secretLen);
            renderCounter(oracleCounter, step.queriesSoFar, 'oracle queries');
          }
          renderCounter(oracleCounter, result.queries, 'oracle queries');
        }

        // Settle the diagram on block 0 — the readable message block — so the
        // final frozen frame shows recovered plaintext, not tag/padding bytes.
        freezeMechBlock(result.steps, 0);

        oracleStatus.className = 'status-line verdict-danger';
        oracleStatus.innerHTML =
          `✗ MtE broken: full plaintext recovered in <span class="stat">${result.queries.toLocaleString()}</span> ` +
          `oracle queries — no key, just pass/fail padding signals. Decrypting before authenticating is the bug.`;
        return;
      }

      // EtM: tamper, then watch the MAC reject it before any decryption.
      // No recovery happens, so blank the mechanism block rather than leaving a
      // stale MtE animation implying a leak.
      initMechBlock();
      if (oracleMech) oracleMech.classList.add('mech-idle');
      const packet = await sealEtM(suite, msg);
      const blocked = await etmRejectsTampering(suite, packet);
      oracleVisual.innerHTML =
        `<div class="recovery">tampered packet → <span class="recovered">rejected at the MAC</span></div>
         <div class="recovery-extra">0 bytes leaked — decryption never ran, so there is nothing to query.</div>`;
      renderCounter(oracleCounter, 0, 'oracle queries possible');
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

// Show the mechanism diagram in an idle (all-pending) state before the first run.
initMechBlock();
if (oracleMech) oracleMech.classList.add('mech-idle');

// ---------------------------------------------------------------------------
// Exhibit 4 — CRIME: recover a secret from compressed length alone.
// ---------------------------------------------------------------------------

const crimeRun = document.querySelector<HTMLButtonElement>('#crime-run');
const crimeReset = document.querySelector<HTMLButtonElement>('#crime-reset');
const crimeSecretEl = document.querySelector<HTMLElement>('#crime-secret');
const crimeVisual = document.querySelector<HTMLElement>('#crime-visual');
const crimeCounter = document.querySelector<HTMLElement>('#crime-counter');
const crimeStatus = document.querySelector<HTMLElement>('#crime-status');
const crimeSecretRun = document.querySelector<HTMLElement>('#crime-secret-run');
const crimeGuessRun = document.querySelector<HTMLElement>('#crime-guess-run');
const crimeSizebar = document.querySelector<HTMLElement>('#crime-sizebar');

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

/**
 * Update the "reflected request" panel: the secret run (masked, revealing the
 * recovered prefix) above the guess run, with the matching prefix highlighted so
 * the shared run DEFLATE back-references is visible. `bestLength` drives a small
 * bar showing that the winning guess's blob is the shortest — the length leak.
 */
function renderCrimeReflect(recovered: string, target: string, bestLength: number | null): void {
  const mask = (s: string, matched: number) => {
    let html = '';
    for (let i = 0; i < s.length; i += 1) {
      const cls = i < matched ? 'crime-run-match' : 'crime-run-dot';
      const ch = i < matched ? escapeHtml(s[i]) : '·';
      html += `<span class="${cls}">${ch}</span>`;
    }
    return html;
  };
  const matched = recovered.length;
  if (crimeSecretRun) crimeSecretRun.innerHTML = mask(target, matched);
  if (crimeGuessRun) crimeGuessRun.innerHTML = mask(recovered.padEnd(target.length, '·'), matched);
  if (crimeSizebar && bestLength !== null) {
    // Shorter blob == stronger match. Show the compressed size as a labelled bar.
    crimeSizebar.innerHTML =
      `<span class="crime-size-label">winning guess compressed to</span>` +
      `<span class="crime-size-val">${bestLength} bytes</span>` +
      `<span class="crime-size-note">(a match shares a longer run → shorter output)</span>`;
  }
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
      renderCrimeReflect('', target, null);
      if (crimeCounter) crimeCounter.innerHTML = '';
      const result = await crimeRecover(target, CRIME_ALPHABET, async (step) => {
        renderCrimeProgress(step.recovered);
        renderCrimeReflect(step.recovered, target, step.bestLength);
        renderCounter(crimeCounter, step.queriesSoFar, 'length measurements');
        if (!prefersReducedMotion) {
          await new Promise((resolve) => setTimeout(resolve, 90));
        }
      });
      renderCrimeProgress(result.recovered);
      renderCounter(crimeCounter, result.queries, 'length measurements');
      const success = result.recovered === target;
      crimeStatus.className = success ? 'status-line verdict-danger' : 'status-line';
      crimeStatus.innerHTML = success
        ? `✗ Full secret recovered in <span class="stat">${result.queries.toLocaleString()}</span> length measurements — no decryption, just compressed size. Each correct character made its blob compress <strong>shorter</strong>.`
        : 'Recovery stalled on compression noise — two characters tied on size this pass (an expected CRIME texture, not a demo bug). Real CRIME repeats and pads the guess to break the tie; press “New secret” to draw a cleaner one.';
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
    renderCrimeReflect('', crimeSecret.replace(/^session=/, ''), null);
    if (crimeSizebar) crimeSizebar.innerHTML = '';
    if (crimeCounter) crimeCounter.innerHTML = '';
    if (crimeStatus) {
      crimeStatus.className = 'status-line';
      crimeStatus.textContent = '';
    }
  });
}

// Seed the reflected-request panel so its structure is visible before the run.
renderCrimeReflect('', crimeSecret.replace(/^session=/, ''), null);

// ---------------------------------------------------------------------------
// Exhibit 3 — timing side-channel: recover a tag from comparison time alone.
// ---------------------------------------------------------------------------

const tmgRun = document.querySelector<HTMLButtonElement>('#tmg-run');
const tmgMode = document.querySelector<HTMLSelectElement>('#tmg-mode');
const tmgSecretEl = document.querySelector<HTMLElement>('#tmg-secret');
const tmgVisual = document.querySelector<HTMLElement>('#tmg-visual');
const tmgCounter = document.querySelector<HTMLElement>('#tmg-counter');
const tmgStatus = document.querySelector<HTMLElement>('#tmg-status');

let tmgRunning = false;
let tmgSecret = randomTag(8);

function renderTmgSecret(): void {
  if (tmgSecretEl) {
    // Shown masked: the point is the attacker recovers it without reading it.
    tmgSecretEl.textContent = Array.from(tmgSecret, () => '··').join(' ');
  }
}
renderTmgSecret();

interface TmgRacing {
  position: number;
  /** 'losing' shows the wrong guesses' short bar; 'winning' the taller bar. */
  phase: 'losing' | 'winning';
}

function renderTmgProgress(
  recovered: (number | null)[],
  comparisons: (number | null)[],
  racing?: TmgRacing,
): string {
  const total = tmgSecret.length;
  const cells = recovered.map((b, i) => {
    const hex = b === null
      ? '<span class="pending">··</span>'
      : `<span class="recovered">${b.toString(16).padStart(2, '0')}</span>`;
    // Bar height ∝ how long the compare ran — the timing tell. During the race we
    // first draw the wrong guesses' short bar, then let the winner edge taller.
    let c = comparisons[i];
    let fillClass = 'tmg-bar-fill';
    if (racing && racing.position === i) {
      const winning = comparisons[i] ?? 1;
      c = racing.phase === 'losing' ? Math.max(winning - 1, 0) : winning;
      fillClass += racing.phase === 'losing' ? ' tmg-bar-losing' : ' tmg-bar-winning';
    }
    const pct = c === null ? 0 : Math.round((c / total) * 100);
    // Numeric readout: comparisons ran -> "how many leading bytes are right".
    let readout = '<span class="tmg-readout-empty">·</span>';
    if (racing && racing.position === i && racing.phase === 'losing') {
      readout = `<span class="tmg-readout-lose">wrong: stops at ${Math.max((comparisons[i] ?? 1) - 1, 0)}/${total}</span>`;
    } else if (c !== null && b !== null) {
      readout = `<span class="tmg-readout-win">ran ${c}/${total} → longest → right</span>`;
    }
    return `<div class="tmg-cell">
      <div class="tmg-bar"><div class="${fillClass}" style="height:${pct}%"></div></div>
      <code>${hex}</code>
      <span class="tmg-readout">${readout}</span>
    </div>`;
  }).join('');
  return `<div class="tmg-track">${cells}</div>`;
}

if (tmgRun && tmgMode && tmgVisual && tmgStatus) {
  tmgRun.addEventListener('click', async () => {
    if (tmgRunning) return;
    tmgRunning = true;
    tmgRun.disabled = true;
    tmgStatus.className = 'status-line';
    writeState();
    try {
      const naive = tmgMode.value !== 'ct';
      const compare: CompareFn = naive ? naiveEqual : constantTimeEqual;
      const recovered: (number | null)[] = new Array(tmgSecret.length).fill(null);
      const comparisons: (number | null)[] = new Array(tmgSecret.length).fill(null);
      tmgVisual.innerHTML = renderTmgProgress(recovered, comparisons);
      if (tmgCounter) tmgCounter.innerHTML = '';
      tmgStatus.textContent = naive
        ? 'Timing the naive compare, one byte at a time…'
        : 'Timing the constant-time compare, one byte at a time…';

      const result = await recoverViaTiming(tmgSecret, compare, async (step) => {
        recovered[step.position] = step.byte;
        comparisons[step.position] = step.comparisons;
        if (prefersReducedMotion) {
          tmgVisual.innerHTML = renderTmgProgress(recovered, comparisons);
        } else {
          // Race: draw the losing guesses' short bar first, then let the winner rise.
          tmgVisual.innerHTML = renderTmgProgress(recovered, comparisons, {
            position: step.position,
            phase: 'losing',
          });
          await new Promise((resolve) => setTimeout(resolve, 130));
          tmgVisual.innerHTML = renderTmgProgress(recovered, comparisons, {
            position: step.position,
            phase: 'winning',
          });
          await new Promise((resolve) => setTimeout(resolve, 90));
        }
        renderCounter(tmgCounter, step.queriesSoFar, 'timed guesses');
      });
      renderCounter(tmgCounter, result.queries, 'timed guesses');

      if (result.success) {
        tmgStatus.className = 'status-line verdict-danger';
        tmgStatus.innerHTML =
          `✗ Naive compare broken: the whole tag recovered in <span class="stat">${result.queries.toLocaleString()}</span> ` +
          `timed guesses — the rising bars are the leak. Early-exit turns "how long did it take" into "how many bytes are right."`;
      } else {
        // Reveal the real tag so the flat bars are unmistakably not a recovery.
        tmgStatus.className = 'status-line verdict-safe';
        tmgStatus.innerHTML =
          '✓ Constant-time compare holds: every guess costs the same work, so the bars are flat and ' +
          'no byte stands out. The attack recovers nothing — the real tag was ' +
          `<code>${toHex(tmgSecret)}</code>.`;
        const revealed = Array.from(tmgSecret, (b) => b as number | null);
        const flat = new Array(tmgSecret.length).fill(tmgSecret.length) as (number | null)[];
        tmgVisual.innerHTML = renderTmgProgress(revealed, flat);
      }
    } catch (e) {
      tmgStatus.className = 'status-line';
      tmgStatus.textContent = 'Error: could not run the timing demo. See console for details.';
      console.error('Timing demo error:', e);
    } finally {
      tmgRunning = false;
      tmgRun.disabled = false;
    }
  });
}

if (tmgMode) {
  tmgMode.addEventListener('change', () => {
    // Fresh tag per run so repeated attacks are not just replaying one recovery.
    tmgSecret = randomTag(8);
    renderTmgSecret();
    if (tmgVisual) tmgVisual.innerHTML = '';
    if (tmgCounter) tmgCounter.innerHTML = '';
    if (tmgStatus) {
      tmgStatus.className = 'status-line';
      tmgStatus.textContent = '';
    }
    writeState();
  });
}

// ---------------------------------------------------------------------------
// Exhibit 5 — TLS evolution walkthrough.
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
// Exhibit 6 — protocol safety checklist.
// ---------------------------------------------------------------------------

const chkRun = document.querySelector<HTMLButtonElement>('#chk-run');
const chkAead = document.querySelector<HTMLSelectElement>('#chk-aead');
const chkEtm = document.querySelector<HTMLSelectElement>('#chk-etm');
const chkOrder = document.querySelector<HTMLSelectElement>('#chk-order');
const chkOutput = document.querySelector<HTMLElement>('#chk-output');

if (chkRun && chkAead && chkEtm && chkOrder && chkOutput) {
  for (const sel of [chkAead, chkEtm, chkOrder]) {
    sel.addEventListener('change', writeState);
  }
  chkRun.addEventListener('click', () => {
    writeState();
    const usesAead = chkAead.value === 'yes';
    const usesEtm = chkEtm.value === 'yes';
    const order = chkOrder.value;

    let kind: 'safe' | 'warn' | 'danger';
    let verdict: string;
    let reason: string;

    if (usesAead) {
      kind = 'safe';
      verdict = 'Safe by design — with one nonce caveat';
      reason = 'A single AEAD primitive authenticates and decrypts together, so composition ordering cannot go wrong here. The one remaining seam is nonce discipline: reuse a nonce with the same key (especially in AES-GCM) and both confidentiality and integrity collapse. Use a counter or random 96-bit nonce and never repeat it.';
    } else if (order === 'etm' && usesEtm) {
      kind = 'warn';
      verdict = 'Acceptable with care';
      reason = 'Encrypt-then-MAC with the MAC verified before decryption is the safe non-AEAD order — but you must also use constant-time tag comparison (Exhibit 3) and a separate MAC key. Prefer AEAD if you can.';
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
}

// ---------------------------------------------------------------------------
// Shareable state + initial run. Apply any ?state from the URL, then fire the
// auto-running exhibits so a shared link reproduces the same configured result.
// ---------------------------------------------------------------------------

applyStateFromUrl();
ex1Run?.click();
chkRun?.click();
