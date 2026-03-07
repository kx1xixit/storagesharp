# Contributing to Storage#

Thank you for your interest in improving Storage#! This guide explains how to set up a development environment, follow the project's conventions, and submit changes.

## Getting started

```bash
git clone https://github.com/kx1xixit/storagesharp.git
cd storagesharp
npm install
```

## Project structure

```
src/
├── 01-core.js        ← All extension logic lives here
└── manifest.json     ← Extension metadata (name, version, license…)

scripts/
├── build.js          ← Bundles src/ → build/extension.js
├── validate.js       ← Validates manifest and extension output
└── eslint-rules/     ← Custom ESLint rules for this project

build/
└── extension.js      ← Generated file — do not edit directly

docs/                 ← Documentation (spell-checked by CSpell)
```

## Development workflow

### Build

```bash
npm run build
```

Produces `build/extension.js`. Load this file in TurboWarp to test your changes.

### Watch mode

```bash
npm run watch
```

Rebuilds automatically whenever a file in `src/` changes.

### Lint

```bash
npm run lint
```

Runs ESLint against `src/` and `scripts/`. Fix errors before opening a PR.

### Auto-fix formatting

```bash
npm run format
```

Runs Prettier over `src/`.

### Spell-check

```bash
npm run spellcheck
```

Checks source files and documentation with CSpell. Add legitimate project-specific words to `cspell.json`.

### Full check (recommended before opening a PR)

```bash
npm run fullstack
```

Runs format → lint → spellcheck → validate → build in sequence.

## Code conventions

### `Scratch.translate()` is required

Every user-visible string in `getInfo()` — the extension `name` and every block `text` — **must** be wrapped in `Scratch.translate()`. This is enforced by a custom ESLint rule and will cause `npm run lint` to fail if violated.

```javascript
// ✓ correct
name: Scratch.translate('Storage#'),
text: Scratch.translate('set key [KEY] to [VALUE]'),

// ✗ wrong — will fail lint
name: 'Storage#',
text: 'set key [KEY] to [VALUE]',
```

### File naming

Source files are numbered so the build script processes them in the right order:

- `01-core.js` — main extension class with `getInfo()` and all block methods
- Additional modules would be `02-*.js`, `03-*.js`, etc.

### Security

- Never commit secrets or credentials.
- All storage keys used by the normal read/write/delete operations are validated through `_isSafeKey()` to prevent prototype pollution.
- If you add new ways to read from or write to storage (including import/export paths), ensure they go through the same `_isSafeKey()`-based safety checks.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Make your changes with focused, well-described commits.
3. Run `npm run fullstack` and confirm it passes.
4. Load `build/extension.js` in TurboWarp and manually verify your changes work.
5. Open a pull request against `main`. Fill in the PR template.

## Reporting bugs

Open an issue and include:

- What you did
- What you expected to happen
- What actually happened
- Browser and TurboWarp version

## Resources

- [TurboWarp Extension API](https://docs.turbowarp.org/development/extensions)
- [Scratch Extension Protocol](https://en.scratch-wiki.info/wiki/Scratch_Extension_Protocol)
- [MDN Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)
- [MDN WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

