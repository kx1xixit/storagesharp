# Storage# — Block Reference

Complete reference for every block provided by the **Storage#** (`kxStorageSharp`) extension.

---

## Configuration blocks

### `set namespace to [NAME]`

**Type:** Command

Switch the active namespace. All subsequent reads and writes are scoped to this namespace. The default namespace is `default`.

Namespaces cannot contain `::` (the internal key separator).

```text
[set namespace to [platformer-v2]]
```

---

### `use [SOURCE] storage`

**Type:** Command

Switch between storage backends:

| Option | Storage API | Persistence |
|---|---|---|
| `Local (Persistent)` | `localStorage` | Survives tab close / browser restart |
| `Session (Temporary)` | `sessionStorage` | Cleared when the tab closes |

```text
[use [Session (Temporary)] storage]
```

---

### `set export encryption key to [KEY]`

**Type:** Command

Set the AES-GCM password used for encrypting and decrypting exported data. Pass an empty string to disable encryption.

```text
[set export encryption key to [myPassword123]]
```

---

## Read / write blocks

### `set key [KEY] to [VALUE]`

**Type:** Command

Write a value to a key. Supports dot-notation for nested objects:

```text
[set key [player.score] to [100]]
[set key [player.name]  to [Alice]]
```

These two writes store a single JSON object at the root key `player`:
`{"score":"100","name":"Alice"}`

---

### `get key [KEY]`

**Type:** Reporter

Read the value stored at a key. Returns `""` if the key does not exist.

```text
(get key [player.score])   → "100"
(get key [missing])        → ""
```

---

### `get object [KEY] as JSON`

**Type:** Reporter

Read a key and return its value as a JSON string. Useful for reading an entire nested object.

```text
(get object [player] as JSON)
→ '{"score":"100","name":"Alice"}'
```

Returns `'{}'` if the key does not exist.

---

### `key [KEY] exists?`

**Type:** Boolean

Returns `true` if the key has a stored value, `false` otherwise.

```text
<key [player.score] exists?>   → true
<key [missing] exists?>        → false
```

---

### `delete key [KEY]`

**Type:** Command

Delete a key. If deleting a nested key leaves an empty parent object, the parent is pruned automatically.

```text
[delete key [player.score]]
```

---

## Versioning blocks

### `set data version to [VER]`

**Type:** Command

Store a version tag for the current namespace. Use this to track save-data schema versions and handle migrations.

```text
[set data version to [2.0]]
```

---

### `get data version`

**Type:** Reporter

Read back the stored version tag. Returns `""` if no version has been set.

```text
(get data version)   → "2.0"
```

---

## Event blocks

### `when storage updates`

**Type:** Event (hat)

Fires whenever a key in the **current namespace** changes. This also triggers when another browser tab modifies the same namespace (cross-tab synchronization via the `storage` DOM event).

```text
when storage updates
set [lastKey] to (last updated key)
```

---

### `last updated key`

**Type:** Reporter

Returns the short key name (without the namespace prefix) that triggered the most recent `when storage updates` event.

---

## Utility blocks

### `storage bytes used`

**Type:** Reporter

Returns the approximate total number of bytes used by the currently active storage backend (across all namespaces, not just the current one).

```text
(storage bytes used)   → 4096
```

---

## Import / export blocks

### `export data`

**Type:** Reporter

Serialize the entire current namespace to a string:

- Without an encryption key → plain JSON string
- With an encryption key → base64-encoded AES-GCM ciphertext

```text
(export data)
```

---

### `import data [DATA_STR]`

**Type:** Command

Restore a namespace from a previously exported string. If an encryption key is set, the input is decrypted first; if decryption fails, the import is aborted and a warning is logged.

```text
[import data [(export data)]]
```

---

### `download export as [FILENAME]`

**Type:** Command

Trigger a browser file download of the exported namespace:

- Plain export → `<FILENAME>.json`
- Encrypted export → `<FILENAME>.enc`

```text
[download export as [my-game-save]]
```

---

### `clear all data in namespace`  ⚠

**Type:** Command (dangerous)

Permanently delete every key stored under the current namespace. This action cannot be undone.

```text
[clear all data in namespace]
```

