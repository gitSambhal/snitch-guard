/**
 * Neutralinojs Client Library Mock (for standalone client execution / prototype)
 * In production `neu run` / `neu build`, this is automatically supplied by the Neutralino CLI.
 */
var Neutralino = {
  init: function() {
    console.log('[Neutralino] Initialized client API');
  },
  app: {
    exit: function() {
      console.log('[Neutralino] app.exit() called');
    }
  },
  window: {
    minimize: function() { console.log('[Neutralino] window.minimize()'); },
    maximize: function() { console.log('[Neutralino] window.maximize()'); },
    unmaximize: function() { console.log('[Neutralino] window.unmaximize()'); },
    isMaximized: async function() { return false; },
    show: function() { console.log('[Neutralino] window.show()'); },
    focus: function() { console.log('[Neutralino] window.focus()'); }
  },
  os: {
    setTray: async function(tray) {
      console.log('[Neutralino] os.setTray()', tray);
    }
  },
  events: {
    on: function(event, handler) {
      window.addEventListener(event, handler);
    }
  }
};
