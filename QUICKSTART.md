# Quick Start — Storage#

Get Storage# running in your TurboWarp project in minutes.

## Prerequisites

- [TurboWarp](https://turbowarp.org) (custom extensions require the desktop app or a compatible fork for unsandboxed mode)
- Node.js 18+ if you want to build from source

## Option A: Load a pre-built release

1. Download `extension.js` from the [latest release](https://github.com/kx1xixit/storagesharp/releases/latest)
2. Open TurboWarp
3. Click **Add Extension** → **Load Custom Extension**
4. Upload the file — the **Storage#** category will appear in the block palette

## Option B: Build from source

```bash
git clone https://github.com/kx1xixit/storagesharp.git
cd storagesharp
npm install
npm run build
```

Then load `build/extension.js` in TurboWarp as above.

## Your first save/load

### Save a value

```text
when green flag clicked
[set namespace to [my-game]]
[set key [player.score] to [0]]
```

### Load a value

```text
when green flag clicked
set [score] to (get key [player.score])
```

### Check if data exists

```text
if <key [player.score] exists?> then
  set [score] to (get key [player.score])
else
  [set key [player.score] to [0]]
end
```

## Namespaces

Namespaces keep data from different projects separate. Always set a namespace before reading or writing:

```text
[set namespace to [platformer-v1]]
```

## Local vs. session storage

By default Storage# uses `localStorage` (data persists after the tab closes). Switch to `sessionStorage` for data that should only last for the current tab session:

```text
[use [Session (Temporary)] storage]
```

## Exporting and importing saves

```text
(export data)                         → JSON string of the entire namespace
[import data [(export data)]]         → restore from that string
[download export as [my-game-save]]   → save a .json file to disk
```

Add an encryption key before exporting to protect the data:

```text
[set export encryption key to [s3cr3t]]
(export data)    → encrypted base64 string
```

Use the same key when importing to decrypt.

## Common commands reference

| Command | What it does |
|---|---|
| `npm run build` | Compile `src/` → `build/extension.js` |
| `npm run watch` | Rebuild automatically on file changes |
| `npm run lint` | Check source code for errors |
| `npm run format` | Auto-format source code |
| `npm run validate` | Validate manifest and extension structure |

## Need help?

- Full documentation: [README.md](README.md)
- Block reference: [docs/example.md](docs/example.md)
- Report a bug: [open an issue](../../issues/new)

