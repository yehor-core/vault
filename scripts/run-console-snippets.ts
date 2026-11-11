// Runs the console snippets of a report (the wrap-up's "Break it" experiments) in the dev demo, as pasted into
// DevTools one after another, and prints what they log.
//
//   node scripts/run-console-snippets.ts <report.md> [engine...]
//
// The snippets are the report's ```js blocks, in order, run in one scope so later blocks see earlier consts.
// Each engine (default: chromium, firefox and webkit) gets a fresh browser context, so a fresh vault. Every
// console line prints as `[engine] <text>`. Exit 0 means every snippet ran in every engine; 1 means one threw.

import { readFileSync } from 'node:fs';
import { createServer as freePortServer } from 'node:net';
import { join } from 'node:path';
import { chromium, firefox, webkit, type BrowserType, type ConsoleMessage } from 'playwright';
import { createServer } from 'vite';

const ENGINES: Record<string, BrowserType> = { chromium, firefox, webkit };

/** The bodies of the ```js blocks of `markdown`, in document order. */
export function consoleSnippets(markdown: string): string[] {
  return [...markdown.matchAll(/^```js\n([\s\S]*?)^```$/gm)].map((match) => match[1] ?? '');
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = freePortServer();
    server.on('error', reject);
    server.listen(0, () => {
      const address = server.address();
      server.close(() => (typeof address === 'object' && address ? resolve(address.port) : reject(address)));
    });
  });
}

async function text(message: ConsoleMessage): Promise<string> {
  const values = await Promise.all(message.args().map((arg) => arg.jsonValue().catch(() => arg.toString())));
  return values.map((value) => (typeof value === 'string' ? value : JSON.stringify(value))).join(' ');
}

async function runIn(name: string, engine: BrowserType, url: string, body: string): Promise<boolean> {
  const browser = await engine.launch();
  try {
    const page = await browser.newPage();
    const lines: Promise<string>[] = [];
    page.on('console', (message) => {
      if (!message.text().startsWith('[vite]')) lines.push(text(message));
    });
    await page.goto(url);
    await page.locator('#status').filter({ hasText: 'Ready' }).waitFor();
    const error = await page.evaluate(`(async () => {\n${body}\n})()`).then(
      () => undefined,
      (e: unknown) => e,
    );
    for (const line of await Promise.all(lines)) console.log(`[${name}] ${line}`);
    if (error !== undefined) console.log(`[${name}] snippet threw: ${error instanceof Error ? error.message : error}`);
    return error === undefined;
  } finally {
    await browser.close();
  }
}

async function main(args: string[]): Promise<number> {
  const [report, ...names] = args;
  if (report === undefined) {
    console.error('usage: node scripts/run-console-snippets.ts <report.md> [engine...]');
    return 2;
  }
  const unknown = names.filter((name) => !(name in ENGINES));
  if (unknown.length > 0) {
    console.error(`unknown engine: ${unknown.join(', ')} (expected ${Object.keys(ENGINES).join(', ')})`);
    return 2;
  }
  const snippets = consoleSnippets(readFileSync(report, 'utf8'));
  if (snippets.length === 0) {
    console.error(`${report}: no js blocks`);
    return 2;
  }
  // localhost, not 127.0.0.1: the demo needs a secure context, as in playwright.config.ts.
  const port = await freePort();
  const server = await createServer({
    root: join(import.meta.dirname, '..', 'demo'),
    server: { port, strictPort: true, host: 'localhost' },
    logLevel: 'silent',
  });
  await server.listen();
  try {
    let ok = true;
    for (const name of names.length > 0 ? names : Object.keys(ENGINES)) {
      ok = (await runIn(name, ENGINES[name] ?? chromium, `http://localhost:${port}/`, snippets.join('\n'))) && ok;
    }
    return ok ? 0 : 1;
  } finally {
    await server.close();
  }
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
