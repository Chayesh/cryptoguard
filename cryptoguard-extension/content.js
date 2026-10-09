// ================================================================
// CryptoGuard — Content Script
// Injected at document_start into every page.
// Hooks WebAssembly and Worker early to catch miners before they start.
// ================================================================

(function() {
  "use strict";

  const SIGNATURES = [
    'coinhive', 'coin-hive', 'cryptonight', 'miner.start',
    'deepminer', 'jsecoin', 'crypto-loot', 'webmine',
    'monero', 'hashrate', 'stratum+tcp', 'getjob', 'submitjob',
    'minero.cc', 'coinimp', 'coinblind', 'ppoi.org',
  ];

  let detectionCount = 0;

  // ── Hook Worker to intercept mining web workers ──
  const OrigWorker = window.Worker;
  window.Worker = function(scriptURL, options) {
    const urlStr = (scriptURL || '').toString().toLowerCase();
    const isMiner = SIGNATURES.some(sig => urlStr.includes(sig));

    if (isMiner) {
      detectionCount++;
      console.warn(`[CryptoGuard] Blocked mining Worker: ${scriptURL}`);
      chrome.runtime.sendMessage({
        action : "minerDetected",
        method : "worker_intercept",
        url    : scriptURL,
      });
      // Return a fake worker that does nothing
      return {
        postMessage : () => {},
        terminate   : () => {},
        addEventListener : () => {},
      };
    }
    return new OrigWorker(scriptURL, options);
  };
  window.Worker.prototype = OrigWorker.prototype;

  // ── Hook WebAssembly.instantiate (miners use WASM) ──
  if (typeof WebAssembly !== 'undefined') {
    const origInstantiate = WebAssembly.instantiate;
    WebAssembly.instantiate = async function(bufferSource, importObject) {
      // Check import object for mining-related imports
      if (importObject) {
        const keys = JSON.stringify(Object.keys(importObject)).toLowerCase();
        if (keys.includes('crypto') || keys.includes('hash') || keys.includes('mine')) {
          detectionCount++;
          console.warn('[CryptoGuard] Suspicious WebAssembly instantiation blocked.');
          chrome.runtime.sendMessage({
            action : "minerDetected",
            method : "wasm_intercept",
            url    : window.location.href,
          });
          return Promise.reject(new Error('[CryptoGuard] Mining WASM blocked.'));
        }
      }
      return origInstantiate.apply(this, arguments);
    };
  }

  // ── Scan inline scripts for mining signatures at load ──
  document.addEventListener("DOMContentLoaded", () => {
    const scripts  = document.querySelectorAll('script:not([src])');
    const srcScripts = document.querySelectorAll('script[src]');

    // Check inline scripts
    scripts.forEach(script => {
      const content = (script.textContent || '').toLowerCase();
      const found   = SIGNATURES.filter(sig => content.includes(sig));
      if (found.length > 0) {
        detectionCount++;
        console.warn(`[CryptoGuard] Mining signatures in inline script: ${found.join(', ')}`);
        chrome.runtime.sendMessage({
          action : "minerDetected",
          method : `inline_script: ${found.join(', ')}`,
          url    : window.location.href,
        });
      }
    });

    // Check external script URLs
    srcScripts.forEach(script => {
      const src   = (script.src || '').toLowerCase();
      const found = SIGNATURES.filter(sig => src.includes(sig));
      if (found.length > 0) {
        detectionCount++;
        console.warn(`[CryptoGuard] Mining script URL detected: ${script.src}`);
        chrome.runtime.sendMessage({
          action : "minerDetected",
          method : `script_url: ${found.join(', ')}`,
          url    : script.src,
        });
      }
    });
  });

})();
