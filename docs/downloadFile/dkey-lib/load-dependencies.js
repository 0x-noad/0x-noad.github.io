// Simple CommonJS shim for browser
// This allows require() to work in the browser for the elgamal dependencies

(function() {
  const modules = {};
  const cache = {};
  
  // Simple require shim
  window.require = function(modulePath) {
    if (cache[modulePath]) {
      return cache[modulePath];
    }
    
    // Handle relative paths
    if (modulePath.startsWith('./') || modulePath.startsWith('../')) {
      // For now, we'll need to load these via script tags in order
      // This is a simplified version - in production you'd use a proper bundler
      throw new Error('Relative requires not fully supported. Please bundle dependencies.');
    }
    
    // Handle npm packages (would need to be loaded via CDN or bundled)
    throw new Error('Module ' + modulePath + ' not found. Please bundle dependencies.');
  };
  
  // Module exports shim
  window.module = { exports: {} };
  window.exports = window.module.exports;
})();

