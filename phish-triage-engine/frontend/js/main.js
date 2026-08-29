(function () {
  "use strict";

  var DEFAULT_API = "http://127.0.0.1:8000";
  var EMAIL_LIMIT = 10 * 1024 * 1024;
  var SCREENSHOT_LIMIT = 15 * 1024 * 1024;
  var apiInput = document.getElementById("api-base");
  var apiStatus = document.getElementById("api-status");
  var result = document.getElementById("result");
  var forms = Array.prototype.slice.call(document.querySelectorAll(".intake-form"));
  var routes = {
    "upload-form": "/v1/intake/email/upload",
    "paste-form": "/v1/intake/email/paste",
    "url-form": "/v1/intake/url",
    "ocr-form": "/v1/intake/ocr",
    "screenshot-form": "/v1/intake/screenshot"
  };
  var buttonLabels = {
    "upload-form": "Submit email file",
    "paste-form": "Submit pasted email",
    "url-form": "Submit URL",
    "ocr-form": "Submit OCR text",
    "screenshot-form": "Submit screenshot"
  };
  var normalizedApiBase = window.PteApiBase.normalizedApiBase;

  function currentApiBase() {
    try { return normalizedApiBase(apiInput.value.trim()); }
    catch (_error) { return DEFAULT_API; }
  }

  function updateActions(base) {
    forms.forEach(function (form) { form.action = base + routes[form.id]; });
  }

  try {
    var storedApi = window.localStorage.getItem("pte-api-base");
    if (storedApi) apiInput.value = normalizedApiBase(storedApi);
  } catch (_error) {
    apiInput.value = DEFAULT_API;
    try { window.localStorage.removeItem("pte-api-base"); } catch (_storageError) { /* Non-fatal. */ }
  }
  updateActions(currentApiBase());

  document.getElementById("save-api-base").addEventListener("click", function () {
    try {
      var base = normalizedApiBase(apiInput.value.trim());
      apiInput.value = base;
      updateActions(base);
      try { window.localStorage.setItem("pte-api-base", base); } catch (_error) { /* Non-fatal. */ }
      apiStatus.textContent = "API address updated.";
      apiStatus.classList.remove("error");
    } catch (error) {
      apiStatus.textContent = error.message || "Enter a valid API address.";
      apiStatus.classList.add("error");
      apiInput.focus();
    }
  });

  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]:not([disabled])'));
  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () { activateTab(tab); });
    tab.addEventListener("keydown", function (event) {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      var index = tabs.indexOf(tab);
      if (event.key === "ArrowRight") index = (index + 1) % tabs.length;
      if (event.key === "ArrowLeft") index = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "Home") index = 0;
      if (event.key === "End") index = tabs.length - 1;
      activateTab(tabs[index]);
      tabs[index].focus();
    });
  });

  function activateTab(active) {
    document.querySelectorAll('[role="tab"]').forEach(function (tab) {
      var selected = tab === active;
      tab.setAttribute("aria-selected", String(selected));
      if (!tab.disabled) tab.tabIndex = selected ? 0 : -1;
      var panel = document.getElementById(tab.getAttribute("aria-controls"));
      if (panel) panel.hidden = !selected;
    });
  }

  var uploadForm = document.getElementById("upload-form");
  var pasteForm = document.getElementById("paste-form");
  var urlForm = document.getElementById("url-form");
  var ocrForm = document.getElementById("ocr-form");
  var screenshotForm = document.getElementById("screenshot-form");
  var fileInput = document.getElementById("email-file");
  var dropZone = document.getElementById("drop-zone");
  var fileFeedback = document.getElementById("file-feedback");
  var screenshotInput = document.getElementById("screenshot-file");
  var screenshotFeedback = document.getElementById("screenshot-feedback");

  function validateEmailFile(file) {
    if (!file) return "Choose an .eml or .msg file.";
    var extension = file.name.toLowerCase().split(".").pop();
    if (extension !== "eml" && extension !== "msg") return "Unsupported file type. Choose an .eml or .msg file.";
    if (file.size > EMAIL_LIMIT) return "This file exceeds the 10 MiB email limit.";
    return "";
  }

  function showEmailFile(file) {
    var error = validateEmailFile(file);
    fileInput.setCustomValidity(error);
    fileFeedback.classList.toggle("error", Boolean(error));
    if (error) {
      fileFeedback.textContent = error;
      dropZone.classList.remove("has-file");
    } else {
      var typeNote = file.name.toLowerCase().endsWith(".msg") ? " — preservation only; headers will not be parsed" : " — ready to submit";
      fileFeedback.textContent = "Selected: " + file.name + " (" + formatBytes(file.size) + ")" + typeNote;
      dropZone.classList.add("has-file");
    }
  }

  function validateScreenshotFile(file) {
    if (!file) return "Choose a PNG, JPEG, WebP, or PDF file.";
    var extension = "." + file.name.toLowerCase().split(".").pop();
    var types = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".pdf": "application/pdf" };
    if (!types[extension] || file.type !== types[extension]) return "File type and extension must match PNG, JPEG, WebP, or PDF.";
    if (file.size > SCREENSHOT_LIMIT) return "This file exceeds the 15 MiB screenshot limit.";
    return "";
  }

  function showScreenshotFile(file) {
    var error = validateScreenshotFile(file);
    screenshotInput.setCustomValidity(error);
    screenshotFeedback.classList.toggle("error", Boolean(error));
    screenshotFeedback.textContent = error || "Selected: " + file.name + " (" + formatBytes(file.size) + ") — ready to submit";
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
  }

  fileInput.addEventListener("change", function () { showEmailFile(fileInput.files[0]); });
  screenshotInput.addEventListener("change", function () { showScreenshotFile(screenshotInput.files[0]); });
  ["dragenter", "dragover"].forEach(function (name) {
    dropZone.addEventListener(name, function (event) { event.preventDefault(); dropZone.classList.add("is-dragging"); fileFeedback.textContent = "Release to select this file."; });
  });
  ["dragleave", "drop"].forEach(function (name) {
    dropZone.addEventListener(name, function (event) { event.preventDefault(); dropZone.classList.remove("is-dragging"); });
  });
  dropZone.addEventListener("drop", function (event) {
    if (!event.dataTransfer.files.length) return;
    try { fileInput.files = event.dataTransfer.files; } catch (_error) { /* Older browsers can still use the chooser. */ }
    showEmailFile(event.dataTransfer.files[0]);
  });

  var modeInputs = document.querySelectorAll('input[name="mode"]');
  var headersField = document.getElementById("headers-field");
  var headersInput = document.getElementById("raw-headers");
  modeInputs.forEach(function (input) {
    input.addEventListener("change", function () {
      if (!input.checked) return;
      var full = input.value === "headers_body";
      headersField.hidden = !full;
      headersInput.required = full;
    });
  });

  function attestationsComplete(form) {
    return form.elements.authorization_attested.checked && form.elements.no_credentials_acknowledged.checked;
  }

  function syncGate(form) {
    form.querySelector(".submit-button").disabled = !attestationsComplete(form);
  }

  forms.forEach(function (form) {
    form.querySelectorAll('input[type="checkbox"]').forEach(function (checkbox) {
      checkbox.addEventListener("change", function () { syncGate(form); });
    });
    syncGate(form);
    form.addEventListener("submit", submitForm);
  });

  function validateRoute(form) {
    if (form === uploadForm) showEmailFile(fileInput.files[0]);
    if (form === screenshotForm) {
      showScreenshotFile(screenshotInput.files[0]);
      var optionalOcr = form.elements.ocr_text;
      optionalOcr.setCustomValidity(optionalOcr.value && !optionalOcr.value.trim() ? "Optional OCR text cannot contain only whitespace." : "");
    }
    if (form === urlForm) {
      var input = form.elements.url;
      try {
        var parsed = new URL(input.value);
        input.setCustomValidity(parsed.protocol === "http:" || parsed.protocol === "https:" ? "" : "Use an HTTP or HTTPS URL.");
      } catch (_error) { input.setCustomValidity("Enter a valid absolute URL."); }
    }
    if (form === pasteForm) {
      var bytes = new TextEncoder().encode((headersInput.value || "") + "\r\n\r\n" + form.elements.body.value).length;
      if (bytes > EMAIL_LIMIT) { showError("The pasted email exceeds the 10 MiB limit. Nothing was submitted."); return false; }
    }
    return form.reportValidity();
  }

  function jsonBody(form) {
    var common = {
      tenant_uid: form.elements.tenant_uid.value.trim(),
      authorization_attested: true,
      no_credentials_acknowledged: true
    };
    if (form === pasteForm) return Object.assign(common, { mode: form.elements.mode.value, raw_headers: form.elements.mode.value === "headers_body" ? headersInput.value : null, body: form.elements.body.value });
    if (form === urlForm) return Object.assign(common, { url: form.elements.url.value });
    var confidence = form.elements.confidence.value;
    return Object.assign(common, { ocr_text: form.elements.ocr_text.value, platform: form.elements.platform.value.trim() || null, engine: form.elements.engine.value.trim() || null, confidence: confidence === "" ? null : Number(confidence) });
  }

  async function submitForm(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!attestationsComplete(form)) { showError("Confirm both required attestations before submitting."); return; }
    if (!validateRoute(form)) return;
    var button = form.querySelector(".submit-button");
    button.disabled = true;
    button.textContent = "Submitting…";
    result.innerHTML = "<p>Submitting evidence to the configured API…</p>";
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
    try {
      var multipart = form === uploadForm || form === screenshotForm;
      var options = { method: "POST", headers: { "Accept": "application/json" } };
      if (multipart) options.body = new FormData(form);
      else { options.headers["Content-Type"] = "application/json"; options.body = JSON.stringify(jsonBody(form)); }
      var response = await fetch(form.action, options);
      var payload = await safeJson(response);
      if (!response.ok) throw new Error(safeErrorMessage(response.status));
      showSuccess(payload);
      form.reset();
      if (form === uploadForm) { dropZone.classList.remove("has-file"); fileFeedback.textContent = ""; }
      if (form === screenshotForm) screenshotFeedback.textContent = "";
      if (form === pasteForm) { headersField.hidden = false; headersInput.required = true; }
    } catch (error) {
      showError(error.message || "Submission failed. No sensitive response content is displayed.");
    } finally {
      button.textContent = buttonLabels[form.id];
      syncGate(form);
    }
  }

  async function safeJson(response) {
    var type = response.headers.get("content-type") || "";
    if (!type.includes("application/json")) return null;
    try { return await response.json(); } catch (_error) { return null; }
  }

  function safeErrorMessage(status) {
    var generic = { 400: "The request was rejected. Confirm both attestations and try again.", 404: "The tenant or intake endpoint was not found.", 409: "The intake could not be persisted. Try again or contact an administrator.", 413: "The evidence exceeds the allowed size limit.", 422: "The evidence or request fields did not pass validation.", 503: "The intake service is temporarily unavailable." }[status];
    return (generic || "Submission failed (HTTP " + status + ").") + " Nothing from the submitted evidence or API response is shown.";
  }

  function safeValue(value) {
    return typeof value === "string" || typeof value === "number" ? String(value) : "Unavailable";
  }

  function showSuccess(payload) {
    result.replaceChildren();
    var heading = document.createElement("p"); heading.className = "result-success"; heading.textContent = "Evidence accepted"; result.appendChild(heading);
    var note = document.createElement("p"); note.textContent = "Only safe intake metadata is shown. Submitted content and other response fields are never displayed here."; result.appendChild(note);
    var list = document.createElement("dl"); list.className = "metadata";
    [["Job ID", payload && payload.job_id], ["Submission ID", payload && payload.submission_id], ["Source type", payload && payload.source_type], ["Fidelity", payload && payload.fidelity], ["State", payload && payload.state]].forEach(function (item) {
      var dt = document.createElement("dt"); dt.textContent = item[0];
      var dd = document.createElement("dd"); dd.textContent = safeValue(item[1]);
      list.appendChild(dt); list.appendChild(dd);
    });
    result.appendChild(list);
  }

  function showError(message) {
    result.replaceChildren();
    var heading = document.createElement("p"); heading.className = "result-error"; heading.textContent = "Submission not accepted";
    var note = document.createElement("p"); note.textContent = message;
    result.appendChild(heading); result.appendChild(note);
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}());
