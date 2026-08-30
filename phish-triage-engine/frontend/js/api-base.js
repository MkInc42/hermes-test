(function (root, factory) {
  "use strict";

  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.PteApiBase = api;
}(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  var LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]"];

  function isHttpLocation(location) {
    return location && (location.protocol === "http:" || location.protocol === "https:");
  }

  function defaultApiBase(location) {
    if (!isHttpLocation(location)) return "http://127.0.0.1:8000";
    var port = LOOPBACK_HOSTS.includes(location.hostname) ? "8000" : "8012";
    return location.protocol + "//" + location.hostname + ":" + port;
  }

  function normalizedApiBase(value, location) {
    var url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("Use an HTTP or HTTPS address.");
    }
    if (url.username || url.password) throw new Error("Credentials are not allowed in the API address.");
    var samePageHost = isHttpLocation(location) && url.hostname === location.hostname;
    if (!LOOPBACK_HOSTS.includes(url.hostname) && !samePageHost) {
      throw new Error("Use a loopback API address or the same host as this page.");
    }
    if (url.pathname !== "/" || url.search || url.hash || url.href !== url.origin + "/") {
      throw new Error("Use an API origin without a path, query string, or fragment.");
    }
    return url.origin;
  }

  return { defaultApiBase: defaultApiBase, normalizedApiBase: normalizedApiBase };
}));
