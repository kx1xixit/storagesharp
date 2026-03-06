#!/usr/bin/env node
/**
 * Runtime test for the built extension.
 * Uses createRequire to load build/extension.js as CommonJS so top-level
 * runtime errors (e.g. bare require calls, reference errors) are caught.
 * Also reports bundle size and block count.
 */

import { createRequire } from 'module';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const BUILD_FILE = path.join(__dirname, '../build/extension.js');

// Provide a minimal Scratch stub so the extension IIFE can register
let registeredExtension = null;

// Stub window and browser storage APIs for Node.js environment
if (typeof globalThis.window === 'undefined') {
  const storageFactory = () => {
    const store = {};
    return {
      getItem: key => (Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null),
      setItem: (key, val) => { store[key] = String(val); },
      removeItem: key => { delete store[key]; },
      key: i => Object.keys(store)[i] ?? null,
      get length() { return Object.keys(store).length; },
      clear: () => { for (const k of Object.keys(store)) delete store[k]; },
    };
  };
  globalThis.window = {
    addEventListener: () => {},
    removeEventListener: () => {},
    localStorage: storageFactory(),
    sessionStorage: storageFactory(),
    crypto: {
      subtle: {},
      getRandomValues: arr => arr,
    },
  };
  globalThis.localStorage = globalThis.window.localStorage;
  globalThis.sessionStorage = globalThis.window.sessionStorage;
  globalThis.document = { createElement: () => ({}), body: { appendChild: () => {}, removeChild: () => {} } };
  globalThis.URL = { createObjectURL: () => '', revokeObjectURL: () => {} };
  globalThis.Blob = class Blob {};
  globalThis.TextEncoder = class TextEncoder { encode(s) { return Buffer.from(s); } };
  globalThis.TextDecoder = class TextDecoder { decode(b) { return b.toString(); } };
}

globalThis.Scratch = {
  extensions: {
    unsandboxed: true,
    register: ext => {
      registeredExtension = ext;
    },
    onShutdown: () => {},
  },
  translate: str => str,
  BlockType: {
    COMMAND: 'command',
    REPORTER: 'reporter',
    BOOLEAN: 'boolean',
    EVENT: 'event',
    HAT: 'hat',
    CONDITIONAL: 'conditional',
    LOOP: 'loop',
  },
  ArgumentType: {
    STRING: 'string',
    NUMBER: 'number',
    BOOLEAN: 'boolean',
    COLOR: 'color',
    IMAGE: 'image',
  },
  vm: { runtime: { startHats: () => {} } },
};

require(BUILD_FILE);

// Assert the extension registered itself
if (!registeredExtension) {
  console.error('FAIL: Extension did not call Scratch.extensions.register().');
  process.exit(1);
}

// Assert getInfo() can be called successfully
let info;
try {
  if (typeof registeredExtension.getInfo !== 'function') {
    console.error('FAIL: Registered extension does not have a getInfo() method.');
    process.exit(1);
  }
  info = registeredExtension.getInfo();
} catch (err) {
  const detail = err instanceof Error ? err.message : String(err);
  console.error(`FAIL: getInfo() threw an error: ${detail}`);
  process.exit(1);
}

console.log('Runtime check passed.');

// Report bundle size
const size = (fs.statSync(BUILD_FILE).size / 1024).toFixed(2);
console.log(`Bundle size:   ${size} KB`);

// Report block count via getInfo()
const blockCount = info?.blocks?.length ?? 0;
console.log(`Blocks:        ${blockCount} (extension id: ${info?.id})`);
