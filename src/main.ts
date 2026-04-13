import './style.css';
import { composeAll, createSuite, sealEtM, sealMtE, toHex } from './compose';
import { createMtEPaddingOracle, etmRejectsTampering, recoverMtEPlaintext, tlsEvolutionNotes } from './attacks';

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
  <main class="page">
    <header class="hero">
      <button
        id="theme-toggle"
        type="button"
        class="theme-toggle"
        style="position: absolute; top: 0; right: 0"
        aria-label="Switch to light mode"
      >🌙</button>
      <h1>Protocol Composition Safety</h1>
      <p>
        Why secure primitives can become insecure when composed in the wrong order.
      </p>
    </header>

    <section class="panel" aria-labelledby="ex1-title">
      <h2 id="ex1-title">Exhibit 1 - The Three Orders</h2>
      <p class="note">Run the same message through MtE, EtM, E&M, and AEAD to compare outputs.</p>
      <label for="ex1-message">Message</label>
      <textarea id="ex1-message">transfer=2500&to=alice</textarea>
      <button id="ex1-run" type="button">Encrypt And Authenticate</button>
      <div class="three-grid">
        <article class="card">
          <h3>MAC-then-Encrypt (MtE)</h3>
          <p class="note">MAC plaintext, append tag, then encrypt both.</p>
          <pre id="ex1-mte" class="hex"></pre>
        </article>
        <article class="card">
          <h3>Encrypt-then-MAC (EtM)</h3>
          <p class="note">Encrypt first, MAC ciphertext, verify tag before decrypt.</p>
          <pre id="ex1-etm" class="hex"></pre>
        </article>
        <article class="card">
          <h3>Encrypt-and-MAC (E&M)</h3>
          <p class="note">Encrypt plaintext and MAC plaintext separately.</p>
          <pre id="ex1-eam" class="hex"></pre>
        </article>
      </div>
      <article class="card">
        <h3>AEAD (AES-256-GCM)</h3>
        <p class="note">Confidentiality and integrity in one primitive.</p>
        <pre id="ex1-aead" class="hex"></pre>
      </article>
    </section>

    <section class="panel" aria-labelledby="ex2-title">
      <h2 id="ex2-title">Exhibit 2 - The Padding Oracle</h2>
      <p class="note">MtE must decrypt before MAC verification; EtM blocks tampering before any decryption.</p>
      <label for="oracle-mode">Composition Mode Selector</label>
      <select id="oracle-mode">
        <option value="mte">MtE (vulnerable surface)</option>
        <option value="etm">EtM (surface closed)</option>
      </select>
      <label for="oracle-message">Attack Message</label>
      <input id="oracle-message" value="pay=bob;amt=1337" />
      <button id="oracle-run" type="button">Padding Oracle Runner</button>
      <p class="note">
        Related lab: <a href="https://systemslibrarian.github.io/crypto-lab-padding-oracle/" target="_blank" rel="noreferrer">crypto-lab-padding-oracle</a>
      </p>
      <pre id="oracle-output" class="hex"></pre>
    </section>

    <section class="panel" aria-labelledby="ex3-title">
      <h2 id="ex3-title">Exhibit 3 - The Composition Principle</h2>
      <p><strong>Secure primitives do not compose securely by default</strong>.</p>
      <ul>
        <li>Hash-then-sign length extension: insecure hash composition can break signature assumptions.</li>
        <li>CBC-then-compress (CRIME): compression side-channels can defeat encrypted transport secrecy.</li>
        <li>Sign-then-encrypt (surreptitious forwarding): signed plaintext can be forwarded as transferable proof.</li>
      </ul>
    </section>

    <section class="panel" aria-labelledby="ex4-title">
      <h2 id="ex4-title">Exhibit 4 - TLS Evolution Walkthrough</h2>
      <p class="note">Use controls to animate record-layer composition evolution from TLS 1.0 to TLS 1.3.</p>
      <div class="btn-row">
        <button id="tls-prev" type="button">Previous</button>
        <button id="tls-play" type="button">TLS Evolution Walkthrough</button>
        <button id="tls-next" type="button">Next</button>
      </div>
      <article id="tls-card" class="card"></article>
    </section>

    <section class="panel" aria-labelledby="ex5-title">
      <h2 id="ex5-title">Exhibit 5 - Protocol Safety Checklist</h2>
      <label for="chk-aead">Are you using AEAD?</label>
      <select id="chk-aead">
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </select>
      <label for="chk-etm">Encrypt-then-MAC?</label>
      <select id="chk-etm">
        <option value="yes">Yes</option>
        <option value="no">No</option>
      </select>
      <label for="chk-order">What order?</label>
      <select id="chk-order">
        <option value="etm">EtM</option>
        <option value="mte">MtE</option>
        <option value="eam">E&M</option>
      </select>
      <button id="chk-run" type="button">Compute Safety Score</button>
      <pre id="chk-output" class="hex"></pre>
    </section>

    <footer class="hero">
      <p>"So whether you eat or drink or whatever you do, do it all for the glory of God." - 1 Corinthians 10:31</p>
    </footer>
  </main>
`;

wireThemeToggle();

const suitePromise = createSuite();

const ex1Run = document.querySelector<HTMLButtonElement>('#ex1-run');
const ex1Message = document.querySelector<HTMLTextAreaElement>('#ex1-message');
if (ex1Run && ex1Message) {
  ex1Run.addEventListener('click', async () => {
    const suite = await suitePromise;
    const msg = ex1Message.value;
    const all = await composeAll(suite, msg);
    const mteEl = document.querySelector<HTMLElement>('#ex1-mte');
    const etmEl = document.querySelector<HTMLElement>('#ex1-etm');
    const eamEl = document.querySelector<HTMLElement>('#ex1-eam');
    const aeadEl = document.querySelector<HTMLElement>('#ex1-aead');
    if (mteEl) {
      mteEl.textContent = `iv=${toHex(all.mte.iv)}\nciphertext=${toHex(all.mte.ciphertext)}`;
    }
    if (etmEl) {
      etmEl.textContent = `iv=${toHex(all.etm.iv)}\nciphertext=${toHex(all.etm.ciphertext)}\ntag=${toHex(all.etm.tag)}`;
    }
    if (eamEl) {
      eamEl.textContent = `iv=${toHex(all.eam.iv)}\nciphertext=${toHex(all.eam.ciphertext)}\ntag(plaintext)=${toHex(all.eam.tag)}`;
    }
    if (aeadEl) {
      aeadEl.textContent = `iv=${toHex(all.aead.iv)}\nciphertext=${toHex(all.aead.ciphertext)}\ntag=${toHex(all.aead.tag)}`;
    }
  });
  ex1Run.click();
}

const oracleRun = document.querySelector<HTMLButtonElement>('#oracle-run');
const oracleMode = document.querySelector<HTMLSelectElement>('#oracle-mode');
const oracleMessage = document.querySelector<HTMLInputElement>('#oracle-message');
const oracleOutput = document.querySelector<HTMLElement>('#oracle-output');
if (oracleRun && oracleMode && oracleMessage && oracleOutput) {
  oracleRun.addEventListener('click', async () => {
    const suite = await suitePromise;
    const mode = oracleMode.value;
    const msg = oracleMessage.value;

    if (mode === 'mte') {
      const packet = await sealMtE(suite, msg);
      const oracle = createMtEPaddingOracle(suite, packet);
      const result = await recoverMtEPlaintext(packet, oracle);
      oracleOutput.textContent = 'Recovering bytes...';
      for (const step of result.steps) {
        oracleOutput.textContent = `Recovered so far: ${step.recoveredTextPreview}`;
        // Short delay for visible byte-by-byte progression.
        await new Promise((resolve) => setTimeout(resolve, 8));
      }
      oracleOutput.textContent = [
        `Recovered bytes (includes MAC/padding): ${result.recoveredText}`,
        `Oracle queries: ${result.queries}`,
        'MtE exposed a decrypt-before-auth oracle surface.'
      ].join('\n');
      return;
    }

    const packet = await sealEtM(suite, msg);
    const blocked = await etmRejectsTampering(suite, packet);
    oracleOutput.textContent = blocked
      ? 'EtM check: tampering rejected before decryption. Padding oracle surface disappears.'
      : 'Unexpected result: EtM did not reject tampering early.';
  });
}

const tlsData = tlsEvolutionNotes();
let tlsIndex = 0;
const tlsCard = document.querySelector<HTMLElement>('#tls-card');
const tlsPrev = document.querySelector<HTMLButtonElement>('#tls-prev');
const tlsPlay = document.querySelector<HTMLButtonElement>('#tls-play');
const tlsNext = document.querySelector<HTMLButtonElement>('#tls-next');
let tlsTimer: number | null = null;

const renderTls = (): void => {
  if (!tlsCard) {
    return;
  }
  const point = tlsData[tlsIndex];
  tlsCard.innerHTML = `
    <h3>${point.version}</h3>
    <p><strong>Composition:</strong> ${point.composition}</p>
    <p><strong>Observed Outcome:</strong> ${point.failureOrWin}</p>
    <p><strong>Lesson:</strong> ${point.lesson}</p>
  `;
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
      tlsPlay.textContent = 'TLS Evolution Walkthrough';
      return;
    }
    tlsPlay.textContent = 'Pause Walkthrough';
    tlsTimer = window.setInterval(() => {
      tlsIndex = (tlsIndex + 1) % tlsData.length;
      renderTls();
    }, 1400);
  });
}

const chkRun = document.querySelector<HTMLButtonElement>('#chk-run');
const chkAead = document.querySelector<HTMLSelectElement>('#chk-aead');
const chkEtm = document.querySelector<HTMLSelectElement>('#chk-etm');
const chkOrder = document.querySelector<HTMLSelectElement>('#chk-order');
const chkOutput = document.querySelector<HTMLElement>('#chk-output');

if (chkRun && chkAead && chkEtm && chkOrder && chkOutput) {
  chkRun.addEventListener('click', () => {
    let score = 10;
    let rating = 'critical risk';
    const usesAead = chkAead.value === 'yes';
    const usesEtm = chkEtm.value === 'yes';
    const order = chkOrder.value;

    if (usesAead) {
      score = 100;
      rating = 'safe by design';
    } else if (usesEtm || order === 'etm') {
      score = 78;
      rating = 'acceptable with care';
    } else if (order === 'eam') {
      score = 44;
      rating = 'information leak risk';
    } else if (order === 'mte') {
      score = 24;
      rating = 'padding-oracle risk';
    }

    chkOutput.textContent = [
      `Protocol safety score: ${score}/100`,
      `Risk rating: ${rating}`,
      usesAead
        ? 'Decision: AEAD selected; this subsumes composition ordering concerns.'
        : 'Decision: non-AEAD composition; verify ordering and side-channel resistance explicitly.'
    ].join('\n');
  });
  chkRun.click();
}
