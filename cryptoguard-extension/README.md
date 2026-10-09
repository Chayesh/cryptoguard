# 🛡️ CryptoGuard Browser Extension

Detects and blocks in-browser cryptojacking miners across Chrome, Brave, and Firefox.

## Detection Methods

| Method | Description |
|---|---|
| **Known domain blocking** | Blocks requests to 15+ known mining script CDNs |
| **Script signature scan** | Scans inline + external scripts for mining library signatures |
| **Worker interception** | Hooks `new Worker()` to block mining web workers |
| **WASM monitoring** | Monitors `WebAssembly.instantiate` for suspicious imports |
| **CPU timing analysis** | Detects sustained high CPU usage per tab |

## Install on Chrome / Brave

```
1. Open Chrome → chrome://extensions/
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select this folder (cryptoguard-extension/)
5. Extension appears in toolbar — pin it
```

## Install on Firefox

```
1. Open Firefox → about:debugging
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select manifest.json from this folder
```

> Note: Firefox loads it as temporary — reinstall after browser restart.
> For permanent install, sign it via addons.mozilla.org.

## Icons

Place PNG icons in the icons/ folder:
- icons/icon16.png   (16×16)
- icons/icon48.png   (48×48)
- icons/icon128.png  (128×128)

Generate from any shield emoji or use a free icon generator.

## Files

```
cryptoguard-extension/
├── manifest.json       ← extension config
├── background.js       ← core detection engine
├── content.js          ← injected into every page
├── popup.html          ← extension popup UI
├── popup.js            ← popup logic
├── history.html        ← full alert history page
├── rules/
│   └── mining_block_rules.json  ← domain blocklist
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```
