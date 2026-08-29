(function (root, factory) {
  "use strict";

  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.PteApiBase = api;
}(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]"];

  function normalizedApiBase(value) {
    var url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("Use an HTTP or HTTPS address.");
    }
    if (url.username || url.password) throw new Error("Credentials are not allowed in the API address.");
    if (!LOOPBACK_HOSTS.includes(url.hostname)) throw new Error("Use a loopback API address.");
    if (url.pathname !== "/" || url.search || url.hash || url.href !== url.origin + "/") {
      throw new Error("Use an API origin without a path, query string, or fragment.");
    }
    return url.origin;
  }

  return { normalizedApiBase: normalizedApiBase };
}));
