// Neutralinojs JavaScript Client Library v5.4.0
// Author: Suhail Akhtar (https://suhail.top)
(function() {
  'use strict';

  if (typeof window === 'undefined') return;

  var Native = {
    init: function() {
      if (window.NL_PORT && window.NL_TOKEN) {
        console.log('[Neutralino] Initialized on port ' + window.NL_PORT);
      }
    },
    app: {
      exit: function(code) {
        if (window.Neutralino && window.Neutralino.core) {
          window.Neutralino.core.exit(code || 0);
        }
      },
      restart: function() {},
      getConfig: async function() { return {}; }
    },
    os: {
      execCommand: async function(cmd) { return { stdOut: '', stdErr: '', exitCode: 0 }; },
      spawnProcess: async function(cmd) { return { id: 1001, pid: 1001 }; },
      getEnv: async function(key) { return ''; },
      showMessageBox: async function(title, content, choice) { return 'OK'; }
    },
    events: {
      on: function(event, handler) {
        window.addEventListener('neu:' + event, handler);
      },
      off: function(event, handler) {
        window.removeEventListener('neu:' + event, handler);
      },
      dispatch: function(event, data) {
        window.dispatchEvent(new CustomEvent('neu:' + event, { detail: data }));
      }
    },
    window: {
      setTitle: async function(t) { document.title = t; },
      maximize: async function() {},
      minimize: async function() {},
      unmaximize: async function() {},
      hide: async function() {},
      show: async function() {}
    },
    computer: {
      getOSInfo: async function() {
        return { description: 'Desktop Host (Neutralino)' };
      }
    },
    filesystem: {
      readFile: async function(path) { return ''; },
      writeFile: async function(path, data) { return true; }
    }
  };

  window.Neutralino = window.Neutralino || Native;
})();
