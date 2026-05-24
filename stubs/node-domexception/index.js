// Export the native DOMException provided natively by modern Node.js and browser environments
module.exports = globalThis.DOMException || class DOMException extends Error {
  constructor(message, name) {
    super(message);
    this.name = name || "DOMException";
  }
};
