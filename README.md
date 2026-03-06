# Storage# (StorageSharp)

**Storage#** is a TurboWarp/Scratch 3 extension that provides persistent, namespaced storage for projects. It wraps the browser's `localStorage` and `sessionStorage` APIs and adds namespacing, dot-notation nested key access, versioning, cross-tab event support, and optional AES-GCM encryption for data export.

> **Requires unsandboxed execution.** Storage# must be loaded as an unsandboxed extension because it needs direct access to browser storage APIs.

## Features

- **Namespaced storage** — isolate data by namespace so multiple projects never collide
- **Local & session storage** — choose between persistent (`localStorage`) and tab-scoped (`sessionStorage`) storage
- **Nested keys** — read and write deeply nested values using dot notation (`player.stats.score`)
- **Data versioning** — tag saved data with a version string for migration support
- **Cross-tab events** — a "when storage updates" hat block fires when another tab modifies storage
- **Import / export** — serialize an entire namespace to JSON and restore it later
- **AES-GCM encryption** — optionally encrypt exported data with a password using WebCrypto
- **Downloadable exports** — trigger a file download of the exported namespace directly from a block

## Installation

1. Build the extension:
   ```bash
   npm install
   npm run build
   ```
2. Go to [TurboWarp](https://turbowarp.org)
3. Click **Add Extension** → **Load Custom Extension**
4. Upload `build/extension.js` or paste a hosted URL

## Quick Example

```
[set namespace to [save1]]
[set key [player.score] to [100]]
[set key [player.name] to [Alice]]

(get key [player.score])          → "100"
(get object [player] as JSON)     → {"score":"100","name":"Alice"}
<key [player.score] exists?>      → true
```

## Block Reference

| Block | Type | Description |
|---|---|---|
| `set namespace to [NAME]` | Command | Switch the active namespace. All subsequent reads and writes use this namespace. Default: `default`. |
| `use [SOURCE] storage` | Command | Switch between **Local (Persistent)** and **Session (Temporary)** storage. |
| `set export encryption key to [KEY]` | Command | Set the AES-GCM password used to encrypt/decrypt exported data. Leave empty to disable encryption. |
| `set key [KEY] to [VALUE]` | Command | Write a value. Supports dot-notation for nested objects (`player.stats.score`). |
| `get key [KEY]` | Reporter | Read a value. Returns `""` if the key does not exist. |
| `get object [KEY] as JSON` | Reporter | Read a key as a JSON string. Useful for reading an entire nested object. |
| `key [KEY] exists?` | Boolean | Returns `true` if the key has a stored value. |
| `delete key [KEY]` | Command | Delete a key. Empty parent objects are pruned automatically. |
| `set data version to [VER]` | Command | Store a version tag for the current namespace (e.g. `"1.0"`). |
| `get data version` | Reporter | Read back the stored version tag. |
| `when storage updates` | Event | Fires when any key in the current namespace changes (including from other tabs). |
| `last updated key` | Reporter | The key that triggered the most recent storage update event. |
| `storage bytes used` | Reporter | Approximate total bytes used by the current storage backend. |
| `export data` | Reporter | Serialize the entire namespace to a JSON string (encrypted if a key is set). |
| `import data [DATA_STR]` | Command | Restore a namespace from a previously exported string. |
| `download export as [FILENAME]` | Command | Download the exported namespace as a `.json` (or `.enc` when encrypted) file. |
| `clear all data in namespace` | Command | ⚠ Permanently delete every key in the current namespace. |

## Namespaces

Namespaces prefix every key in storage, keeping projects isolated:

```
[set namespace to [game-v2]]
[set key [score] to [500]]
```

The actual storage key becomes `game-v2::score`. Switching namespaces does not copy or migrate data; you must handle that in your project.

## Dot-Notation Keys

Keys containing `.` are stored as nested JSON objects under a single root key:

```
set key [player.score] to [100]
set key [player.name] to [Alice]

→ localStorage["default::player"] = '{"score":"100","name":"Alice"}'
```

Reading a non-leaf node with `get object [KEY] as JSON` returns the serialized object.

## Encryption

Set an encryption key before exporting to protect save data:

```
[set export encryption key to [s3cr3t]]
(export data)          → base64-encoded AES-GCM ciphertext
```

Import with the same key to decrypt:

```
[set export encryption key to [s3cr3t]]
[import data [(export data)]]
```

Exports without an encryption key are plain JSON.

## Development

```bash
npm install          # Install dependencies
npm run build        # Build build/extension.js
npm run watch        # Rebuild on file changes
npm run lint         # Run ESLint
npm run format       # Auto-format with Prettier
npm run spellcheck   # Spell-check source and docs
npm run validate     # Validate manifest and extension structure
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

KXEC-1.1 — see [LICENSE](LICENSE).
