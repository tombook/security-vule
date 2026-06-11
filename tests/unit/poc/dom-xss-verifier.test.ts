import { describe, it, expect } from 'bun:test';
import {
  DomXssVerifier,
  PIKACHU_DOM_XSS_TARGETS,
  type DomXssTarget,
  type DomXssResult,
} from '../../../src/poc/dom-xss-verifier.js';

describe('DomXssVerifier', () => {
  describe('DomXssTarget definitions', () => {
    it('PIKACHU_DOM_XSS_TARGETS has 2 entries', () => {
      expect(PIKACHU_DOM_XSS_TARGETS.length).toBe(2);
    });

    it('all targets have required fields', () => {
      for (const t of PIKACHU_DOM_XSS_TARGETS) {
        expect(t.id).toBeTruthy();
        expect(t.url).toBeTruthy();
        expect(t.inputSelector).toBeTruthy();
        expect(t.triggerSelector).toBeTruthy();
        expect(t.payload).toBeTruthy();
        expect(t.domSelector).toBeTruthy();
        expect(['inner_html', 'page_error', 'console_log']).toContain(t.detectionMethod);
        expect(t.detectionPattern).toBeTruthy();
      }
    });

    it('inner_html target uses correct detection', () => {
      const innerHtmlTarget = PIKACHU_DOM_XSS_TARGETS.find(
        (t) => t.detectionMethod === 'inner_html'
      );
      expect(innerHtmlTarget).toBeDefined();
      expect(innerHtmlTarget!.payload).toContain('onclick');
    });

    it('page_error target uses onerror payload', () => {
      const errorTarget = PIKACHU_DOM_XSS_TARGETS.find((t) => t.detectionMethod === 'page_error');
      expect(errorTarget).toBeDefined();
      expect(errorTarget!.payload).toContain('onerror');
    });

    it('all Pikachu targets require login', () => {
      for (const t of PIKACHU_DOM_XSS_TARGETS) {
        expect(t.loginRequired).toBe(true);
        expect(t.loginUrl).toBeTruthy();
        expect(t.loginFields).toBeDefined();
      }
    });
  });

  describe('DomXssResult type', () => {
    it('has correct shape', () => {
      const result: DomXssResult = {
        id: 'test',
        success: true,
        domContent: '<a href="">test</a>',
        errors: [],
        logs: [],
        statusCode: 200,
        responseTimeMs: 100,
      };
      expect(result.success).toBe(true);
      expect(result.domContent).toContain('test');
    });
  });

  describe('DomXssVerifier constructor', () => {
    it('creates instance with baseUrl', () => {
      const verifier = new DomXssVerifier({ baseUrl: 'http://localhost:8083' });
      expect(verifier).toBeDefined();
    });
  });
});
