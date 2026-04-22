// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import "@testing-library/jest-dom";
import { config } from "dotenv";

// Load environment variables from .env file for tests
config();

// ============================================================================
// DOM Mocks
// ============================================================================

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => { },
    removeListener: () => { },
    addEventListener: () => { },
    removeEventListener: () => { },
    dispatchEvent: () => { },
  }),
});

// ============================================================================
// Web Crypto API Mock
// ============================================================================

// Mock Web Crypto API if not available (Node.js environment)
if (typeof window !== 'undefined' && !window.crypto) {
  // Note: This is a simplified mock for testing. In real Node.js environments,
  // use the native crypto.webcrypto API
  Object.defineProperty(window, 'crypto', {
    value: {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = Math.floor(Math.random() * 256);
        }
        return arr;
      },
      subtle: {
        // Minimal mock - real tests should use jsdom or similar
      },
    },
  });
}

// ============================================================================
// IndexedDB Mock for Rate Limiter Tests
// ============================================================================

// Simple in-memory IndexedDB mock for testing
class MockIDBDatabase {
  private stores: Map<string, Map<string, unknown>> = new Map();

  createObjectStore(name: string): MockIDBObjectStore {
    if (!this.stores.has(name)) {
      this.stores.set(name, new Map());
    }
    return new MockIDBObjectStore(this.stores.get(name)!);
  }

  transaction(storeNames: string | string[], mode?: string): MockIDBTransaction {
    const stores = Array.isArray(storeNames) ? storeNames : [storeNames];
    return new MockIDBTransaction(
      stores.map(name => {
        if (!this.stores.has(name)) {
          this.stores.set(name, new Map());
        }
        return { name, store: this.stores.get(name)! };
      })
    );
  }
}

class MockIDBObjectStore {
  constructor(private data: Map<string, unknown>) { }

  get(key: string): MockIDBRequest {
    return new MockIDBRequest(this.data.get(key));
  }

  put(value: unknown, key?: string): MockIDBRequest {
    const record = value as Record<string, unknown>;
    const actualKey = key
      || (typeof record?.id === "string" ? record.id : undefined)
      || (typeof record?.key === "string" ? record.key : undefined)
      || Math.random().toString();
    this.data.set(actualKey, value);
    return new MockIDBRequest(actualKey);
  }

  delete(key: string): MockIDBRequest {
    this.data.delete(key);
    return new MockIDBRequest(undefined);
  }

  clear(): MockIDBRequest {
    this.data.clear();
    return new MockIDBRequest(undefined);
  }
}

class MockIDBTransaction {
  constructor(private stores: Array<{ name: string; store: Map<string, unknown> }>) { }

  objectStore(name: string): MockIDBObjectStore {
    const storeData = this.stores.find(s => s.name === name);
    if (!storeData) {
      throw new Error(`Object store ${name} not found`);
    }
    return new MockIDBObjectStore(storeData.store);
  }
}

class MockIDBRequest {
  result: unknown;
  error: Error | null = null;
  onsuccess: ((event: { target: MockIDBRequest }) => void) | null = null;
  onerror: ((event: { target: MockIDBRequest }) => void) | null = null;

  constructor(result: unknown) {
    this.result = result;
    // Simulate async behavior
    setTimeout(() => {
      if (this.onsuccess) {
        this.onsuccess({ target: this });
      }
    }, 0);
  }
}

// Mock indexedDB if not available
if (typeof window !== 'undefined' && !window.indexedDB) {
  const mockDB = new MockIDBDatabase();

  Object.defineProperty(window, 'indexedDB', {
    value: {
      open: (name: string, version?: number) => {
        const request = new MockIDBRequest(mockDB);
        setTimeout(() => {
          if (request.onsuccess) {
            request.onsuccess({ target: request });
          }
        }, 0);
        return request;
      },
      deleteDatabase: (name: string) => {
        return new MockIDBRequest(undefined);
      },
    },
  });
}

// ============================================================================
// Clipboard API Mock
// ============================================================================

// Mock Clipboard API for testing
if (typeof navigator !== 'undefined' && !navigator.clipboard) {
  let clipboardContent = '';

  Object.defineProperty(navigator, 'clipboard', {
    value: {
      writeText: async (text: string) => {
        clipboardContent = text;
      },
      readText: async () => {
        return clipboardContent;
      },
    },
    writable: true,
  });
}

// ============================================================================
// Performance API Mock
// ============================================================================

// Ensure performance.now() is available
if (typeof performance === 'undefined') {
  (global as unknown as { performance: { now: () => number } }).performance = {
    now: () => Date.now(),
  };
}

// ============================================================================
// Security Test Configuration
// ============================================================================

// Note: Test timeout is configured in vitest.config.ts

// Disable console warnings in tests (optional)
const originalWarn = console.warn;
const originalError = console.error;

beforeAll(() => {
  console.warn = (...args: unknown[]) => {
    // Filter out specific warnings if needed
    const firstArg = args[0];
    if (typeof firstArg !== 'string' || !firstArg.includes('Warning: ReactDOM.render')) {
      originalWarn(...args);
    }
  };

  console.error = (...args: unknown[]) => {
    // Filter out specific errors if needed
    const firstArg = args[0];
    if (typeof firstArg !== 'string' || !firstArg.includes('Warning: ReactDOM.render')) {
      originalError(...args);
    }
  };
});

afterAll(() => {
  console.warn = originalWarn;
  console.error = originalError;
});
