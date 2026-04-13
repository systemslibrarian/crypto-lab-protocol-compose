import './style.css';
import { runCompositionDemo } from './compose';
import { runAttackDemo } from './attacks';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root element');
}

app.innerHTML = `
  <main class="page">
    <header class="hero">
      <h1>Protocol Composition Safety</h1>
      <p>Interactive exhibit loading...</p>
    </header>
  </main>
`;

void runCompositionDemo();
void runAttackDemo();
