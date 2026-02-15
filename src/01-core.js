if (!Scratch.extensions.unsandboxed) {
  throw new Error('Storage# needs to run unsandboxed to access browser storage APIs.');
}

const SOURCE_LOCAL = 'local';
const SOURCE_SESSION = 'session';
const MAGIC_SIG = 'SIG:TURBO_SECURE_V1'; // Integrity check header

class StorageSharp {
  constructor(runtime) {
    this.runtime = runtime;
    this.currentNamespace = 'default';
    this.currentSource = SOURCE_LOCAL;
    this.separator = '::';
    this.securityKey = ''; // Renamed for clarity (AES Key)

    this.lastUpdatedKey = '';
    this._onStorageUpdate = this._onStorageUpdate.bind(this);
    window.addEventListener('storage', this._onStorageUpdate);

    // Cleanup listener if extension is unloaded
    if (Scratch.extensions.onShutdown) {
      Scratch.extensions.onShutdown(() => {
        window.removeEventListener('storage', this._onStorageUpdate);
      });
    }
  }

  _isSafeKey(key) {
    // Prevent prototype pollution by blocking dangerous keys
    return key !== '__proto__' && key !== 'prototype' && key !== 'constructor';
  }

  getInfo() {
    return {
      id: 'kxStorageSharp',
      name: 'Storage#',
      color1: '#4a90e2',
      color2: '#357abd',
      blocks: [
        {
          opcode: 'setNamespace',
          blockType: Scratch.BlockType.COMMAND,
          text: 'set namespace to [NAME]',
          arguments: {
            NAME: { type: Scratch.ArgumentType.STRING, defaultValue: 'save1' },
          },
        },
        {
          opcode: 'setSource',
          blockType: Scratch.BlockType.COMMAND,
          text: 'use [SOURCE] storage',
          arguments: {
            SOURCE: { type: Scratch.ArgumentType.STRING, menu: 'storageMenu' },
          },
        },
        {
          opcode: 'setSecurityKey',
          blockType: Scratch.BlockType.COMMAND,
          text: 'set export encryption key to [KEY]',
          arguments: {
            KEY: { type: Scratch.ArgumentType.STRING, defaultValue: '' },
          },
        },
        '---',
        {
          opcode: 'setValue',
          blockType: Scratch.BlockType.COMMAND,
          text: 'set key [KEY] to [VALUE]',
          arguments: {
            KEY: { type: Scratch.ArgumentType.STRING, defaultValue: 'player.score' },
            VALUE: { type: Scratch.ArgumentType.STRING, defaultValue: '100' },
          },
        },
        {
          opcode: 'getValue',
          blockType: Scratch.BlockType.REPORTER,
          text: 'get key [KEY]',
          arguments: {
            KEY: { type: Scratch.ArgumentType.STRING, defaultValue: 'player.score' },
          },
        },
        {
          opcode: 'getObject',
          blockType: Scratch.BlockType.REPORTER,
          text: 'get object [KEY] as JSON',
          arguments: {
            KEY: { type: Scratch.ArgumentType.STRING, defaultValue: 'player' },
          },
        },
        {
          opcode: 'keyExists',
          blockType: Scratch.BlockType.BOOLEAN,
          text: 'key [KEY] exists?',
          arguments: {
            KEY: { type: Scratch.ArgumentType.STRING, defaultValue: 'player.score' },
          },
        },
        {
          opcode: 'deleteKey',
          blockType: Scratch.BlockType.COMMAND,
          text: 'delete key [KEY]',
          arguments: {
            KEY: { type: Scratch.ArgumentType.STRING, defaultValue: 'player.score' },
          },
        },
        '---',
        {
          opcode: 'setVersion',
          blockType: Scratch.BlockType.COMMAND,
          text: 'set data version to [VER]',
          arguments: {
            VER: { type: Scratch.ArgumentType.STRING, defaultValue: '1.0' },
          },
        },
        {
          opcode: 'getVersion',
          blockType: Scratch.BlockType.REPORTER,
          text: 'get data version',
          disableMonitor: true,
        },
        '---',
        {
          opcode: 'whenStorageUpdated',
          blockType: Scratch.BlockType.EVENT, // Corrected from HAT to EVENT
          text: 'when storage updates',
          isEdgeActivated: false,
        },
        {
          opcode: 'getLastUpdatedKey',
          blockType: Scratch.BlockType.REPORTER,
          text: 'last updated key',
          disableMonitor: true,
        },
        {
          opcode: 'getStorageUsage',
          blockType: Scratch.BlockType.REPORTER,
          text: 'storage bytes used',
          disableMonitor: true,
        },
        '---',
        {
          opcode: 'exportNamespace',
          blockType: Scratch.BlockType.REPORTER,
          text: 'export data',
          disableMonitor: true,
        },
        {
          opcode: 'importNamespace',
          blockType: Scratch.BlockType.COMMAND,
          text: 'import data [JSON_STR]',
          arguments: {
            JSON_STR: { type: Scratch.ArgumentType.STRING, defaultValue: '{}' },
          },
        },
        {
          opcode: 'downloadExport',
          blockType: Scratch.BlockType.COMMAND,
          text: 'download export as [FILENAME].json',
          arguments: {
            FILENAME: { type: Scratch.ArgumentType.STRING, defaultValue: 'my-game-save' },
          },
        },
        {
          opcode: 'clearNamespace',
          blockType: Scratch.BlockType.COMMAND,
          text: 'clear all data in namespace',
          isDangerous: true,
        },
      ],
      menus: {
        storageMenu: {
          acceptReporters: true,
          items: [
            { text: 'Local (Persistent)', value: SOURCE_LOCAL },
            { text: 'Session (Temporary)', value: SOURCE_SESSION },
          ],
        },
      },
    };
  }

  // --- Helpers ---

  _getStorage() {
    try {
      if (this.currentSource === SOURCE_SESSION) {
        return window.sessionStorage;
      }
      return window.localStorage;
    } catch (e) {
      console.warn('Storage Manager: Storage not available (Sandbox?)', e);
      return null;
    }
  }

  _makeKey(key) {
    return `${this.currentNamespace}${this.separator}${key}`;
  }

  _isNamespaceKey(fullKey) {
    return fullKey && fullKey.startsWith(`${this.currentNamespace}${this.separator}`);
  }

  _extractKey(fullKey) {
    return fullKey.substring(this.currentNamespace.length + this.separator.length);
  }

  _triggerUpdate(fullKey) {
    if (this._isNamespaceKey(fullKey)) {
      this.lastUpdatedKey = this._extractKey(fullKey);
      this.runtime.startHats('kxStorageSharp_whenStorageUpdated');
    }
  }

  _safeSetItem(storage, key, value) {
    try {
      storage.setItem(key, value);
      return true;
    } catch (e) {
      if (e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED') {
        console.warn('Storage Manager: Save failed - Storage Full (Quota Exceeded)');
      } else {
        console.warn('Storage Manager: Save failed', e);
      }
      return false;
    }
  }

  // --- Nested Object Helpers ---

  _getNested(path, forceJson = false) {
    const parts = path.split('.');
    if (!this._isSafeKey(parts[0])) return null;
    const storage = this._getStorage();
    if (!storage) return null;

    if (parts.length === 1) {
      const val = storage.getItem(this._makeKey(parts[0]));
      return val;
    }

    const rootKey = parts[0];
    const rootVal = storage.getItem(this._makeKey(rootKey));
    if (rootVal === null) return null;

    try {
      let current = JSON.parse(rootVal);
      for (let i = 1; i < parts.length; i++) {
        if (current === undefined || current === null) return null;
        current = current[parts[i]];
      }

      if (typeof current === 'object' || forceJson) {
        return JSON.stringify(current);
      }
      return current;
    } catch (_e) {
      return null;
    }
  }

  _setNested(path, value) {
    const parts = path.split('.');
    const storage = this._getStorage();
    if (!storage) return;
    const fullRootKey = this._makeKey(parts[0]);

    if (parts.length === 1) {
      if (!this._isSafeKey(parts[0])) return;
      this._safeSetItem(storage, fullRootKey, JSON.stringify(value));
      this._triggerUpdate(fullRootKey);
      return;
    }

    let rootObj = {};
    try {
      const existing = storage.getItem(fullRootKey);
      if (existing) rootObj = JSON.parse(existing);
      if (typeof rootObj !== 'object' || rootObj === null) rootObj = {};
    } catch (_e) {
      rootObj = {};
    }

    let current = rootObj;
    for (let i = 1; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!this._isSafeKey(part)) {
        return;
      }
      if (!current[part] || typeof current[part] !== 'object') {
        current[part] = {};
      }
      current = current[part];
    }

    const leafKey = parts[parts.length - 1];
    if (!this._isSafeKey(leafKey)) {
      return;
    }
    current[leafKey] = value;
    this._safeSetItem(storage, fullRootKey, JSON.stringify(rootObj));
    this._triggerUpdate(fullRootKey);
  }

  _deleteNested(path) {
    const parts = path.split('.');
    if (!this._isSafeKey(parts[0])) return;
    const storage = this._getStorage();
    if (!storage) return;
    const fullRootKey = this._makeKey(parts[0]);

    if (parts.length === 1) {
      storage.removeItem(fullRootKey);
      this._triggerUpdate(fullRootKey);
      return;
    }

    try {
      const existing = storage.getItem(fullRootKey);
      if (!existing) return;
      const rootObj = JSON.parse(existing);

      const stack = [];
      let current = rootObj;

      for (let i = 1; i < parts.length - 1; i++) {
        const key = parts[i];
        if (!this._isSafeKey(key)) {
          return;
        }
        if (!current[key]) return;
        stack.push({ parent: current, key });
        current = current[key];
      }

      const leafKey = parts[parts.length - 1];
      if (!this._isSafeKey(leafKey)) {
        return;
      }
      if (current && Object.prototype.hasOwnProperty.call(current, leafKey)) {
        delete current[leafKey];
      }

      for (let i = stack.length - 1; i >= 0; i--) {
        const { parent, key } = stack[i];
        const child = parent[key];
        if (typeof child === 'object' && Object.keys(child).length === 0) {
          delete parent[key];
        } else {
          break;
        }
      }

      if (Object.keys(rootObj).length === 0) {
        storage.removeItem(fullRootKey);
      } else {
        this._safeSetItem(storage, fullRootKey, JSON.stringify(rootObj));
      }
      this._triggerUpdate(fullRootKey);
    } catch (_e) {
      // Ignore
    }
  }

  // --- WebCrypto AES-GCM Implementation ---

  async _generateKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async _encrypt(text) {
    if (!this.securityKey) return text;
    try {
      const enc = new TextEncoder();
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));

      const key = await this._generateKey(this.securityKey, salt);
      const dataToEncrypt = MAGIC_SIG + text;

      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        enc.encode(dataToEncrypt)
      );

      const buffer = new Uint8Array(salt.byteLength + iv.byteLength + encrypted.byteLength);
      buffer.set(salt, 0);
      buffer.set(iv, salt.byteLength);
      buffer.set(new Uint8Array(encrypted), salt.byteLength + iv.byteLength);

      let binary = '';
      const len = buffer.byteLength;
      for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(buffer[i]);
      }
      return btoa(binary);
    } catch (e) {
      console.warn('Storage Manager: Encryption failed:', e);
      return null;
    }
  }

  async _decrypt(text) {
    if (!this.securityKey) return text;
    try {
      const binary = atob(text);
      const buffer = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
      }

      const salt = buffer.slice(0, 16);
      const iv = buffer.slice(16, 28);
      const data = buffer.slice(28);

      const key = await this._generateKey(this.securityKey, salt);

      const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);

      const decryptedText = new TextDecoder().decode(decrypted);

      if (!decryptedText.startsWith(MAGIC_SIG)) {
        throw new Error('Integrity signature mismatch. Incorrect password?');
      }

      return decryptedText.substring(MAGIC_SIG.length);
    } catch (e) {
      console.warn('Storage Manager: Decryption failed (Wrong password or corrupted data)', e);
      return null;
    }
  }

  // --- Event Handlers ---

  _onStorageUpdate(e) {
    if (e.key && this._isNamespaceKey(e.key)) {
      this._triggerUpdate(e.key);
    }
  }

  // --- Block Implementations ---

  setNamespace(args) {
    const name = String(args.NAME);
    if (name.includes(this.separator)) {
      console.warn(`Namespace cannot contain '${this.separator}'`);
      return;
    }
    this.currentNamespace = name;
  }

  setSource(args) {
    const allowedSources = [SOURCE_LOCAL, SOURCE_SESSION];
    const source = String(args.SOURCE);
    if (!allowedSources.includes(source)) {
      console.warn(`Storage Manager: Invalid source '${source}'.`);
      return;
    }
    this.currentSource = source;
  }

  setSecurityKey(args) {
    this.securityKey = String(args.KEY);
  }

  setValue(args) {
    this._setNested(args.KEY, args.VALUE);
  }

  getValue(args) {
    const val = this._getNested(args.KEY);
    return val === null ? '' : val;
  }

  getObject(args) {
    const val = this._getNested(args.KEY, true);
    return val === null ? '{}' : val;
  }

  keyExists(args) {
    return this._getNested(args.KEY) !== null;
  }

  deleteKey(args) {
    this._deleteNested(args.KEY);
  }

  setVersion(args) {
    const storage = this._getStorage();
    if (!storage) return;
    const fullKey = this._makeKey('__version__');
    this._safeSetItem(storage, fullKey, String(args.VER));
  }

  getVersion() {
    const storage = this._getStorage();
    if (!storage) return '';
    const fullKey = this._makeKey('__version__');
    const val = storage.getItem(fullKey);
    return val === null ? '' : val;
  }

  clearNamespace() {
    const storage = this._getStorage();
    if (!storage) return;

    const keysToRemove = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (this._isNamespaceKey(key)) {
        keysToRemove.push(key);
      }
    }

    keysToRemove.forEach(key => {
      storage.removeItem(key);
    });
    this._triggerUpdate(this._makeKey('__cleared__'));
  }

  async exportNamespace() {
    const storage = this._getStorage();
    if (!storage) return '{}';

    const exportObj = {};
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (this._isNamespaceKey(key)) {
        const cleanKey = this._extractKey(key);
        const val = storage.getItem(key);
        try {
          exportObj[cleanKey] = JSON.parse(val);
        } catch (_e) {
          exportObj[cleanKey] = val;
        }
      }
    }
    const json = JSON.stringify(exportObj);

    if (this.securityKey) {
      const encrypted = await this._encrypt(json);
      return encrypted || '';
    }
    return json;
  }

  async importNamespace(args) {
    const storage = this._getStorage();
    if (!storage) return;

    let jsonStr = args.JSON_STR;

    if (this.securityKey) {
      const decrypted = await this._decrypt(jsonStr);
      if (decrypted === null) {
        console.warn('Import failed: Decryption integrity check failed.');
        return;
      }
      jsonStr = decrypted;
    }

    let data;
    try {
      data = JSON.parse(jsonStr);
    } catch (_e) {
      console.warn('Storage Manager: Invalid JSON import format');
      return;
    }

    if (typeof data !== 'object' || data === null) return;

    Object.keys(data).forEach(key => {
      const fullKey = this._makeKey(key);
      const val = data[key];
      const toStore = typeof val === 'object' ? JSON.stringify(val) : String(val);
      this._safeSetItem(storage, fullKey, toStore);
      this._triggerUpdate(fullKey);
    });
  }

  async downloadExport(args) {
    const content = await this.exportNamespace();
    const fileName = (args.FILENAME || 'data') + (this.securityKey ? '.enc' : '.json');

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  getLastUpdatedKey() {
    return this.lastUpdatedKey;
  }

  getStorageUsage() {
    const storage = this._getStorage();
    if (!storage) return 0;

    const enc = new TextEncoder();
    let totalBytes = 0;
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      const value = storage.getItem(key);
      totalBytes += enc.encode(key).length;
      if (value !== null) {
        totalBytes += enc.encode(value).length;
      }
    }
    return totalBytes;
  }
}

Scratch.extensions.register(new StorageSharp(Scratch.vm.runtime));
