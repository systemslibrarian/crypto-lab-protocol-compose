import './style.css';
import { runCompositionDemo } from './compose';
import { runAttackDemo } from './attacks';

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
      <p>Interactive exhibit loading...</p>
    </header>
  </main>
`;

wireThemeToggle();
void runCompositionDemo();
void runAttackDemo();
