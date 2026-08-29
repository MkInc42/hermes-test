(function () {
  "use strict";

  var DEFAULT_API = "http://127.0.0.1:8000";
  var EMAIL_LIMIT = 10 * 1024 * 1024;
  var apiInput = document.getElementById("api-base");
  var apiStatus = document.getElementById("api-status");
  var result = document.getElementById("result");
  var forms = [document.getElementById("upload-form"), document.getElementById("paste-form")];

  function normalizedApiBase(value) {
    var url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("Use an HTTP or HTTPS address.");
    return url.href.replace(/\/$/, "");
  }

  function currentApiBase() {
    try { return normalizedApiBase(apiInput.value.trim()); }
    catch (_error) { return DEFAULT_API; }
  }

  function updateActions(base) {
    forms[0].action = base + "/v1/intake/email/upload";
    forms[1].action = base + "/v1/intake/email/paste";
  }

  try {
    var storedApi = window.localStorage.getItem("pte-api-base");
    if (storedApi) apiInput.value = normalizedApiBase(storedApi);
  } catch (_error) { /* Storage may be unavailable; the loopback default remains usable. */ }
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
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight" && event.key !== "Home" && event.key !== "End") return;
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

  var fileInput = document.getElementById("email-file");
  var dropZone = document.getElementById("drop-zone");
  var fileFeedback = document.getElementById("file-feedback");

  function validateFile(file) {
    if (!file) return "Choose an .eml or .msg file.";
    var extension = file.name.toLowerCase().split(".").pop();
    if (extension !== "eml" && extension !== "msg") return "Unsupported file type. Choose an .eml or .msg file.";
    if (file.size > EMAIL_LIMIT) return "This file exceeds the 10 MiB email limit.";
    return "";
  }

  function showFile(file) {
    var error = validateFile(file);
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
    syncGate(forms[0]);
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KiB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
  }

  fileInput.addEventListener("change", function () { showFile(fileInput.files[0]); });
  ["dragenter", "dragover"].forEach(function (name) {
    dropZone.addEventListener(name, function (event) { event.preventDefault(); dropZone.classList.add("is-dragging"); fileFeedback.textContent = "Release to select this file."; });
  });
  ["dragleave", "drop"].forEach(function (name) {
    dropZone.addEventListener(name, function (event) { event.preventDefault(); dropZone.classList.remove("is-dragging"); });
  });
  dropZone.addEventListener("drop", function (event) {
    if (!event.dataTransfer.files.length) return;
    try { fileInput.files = event.dataTransfer.files; } catch (_error) { /* Older browsers can still use the chooser. */ }
    showFile(event.dataTransfer.files[0]);
  });

  var modeInputs = document.querySelectorAll('input[name="mode"]');
  var headersField = document.getElementById("headers-field");
  var headersInput = document.getElementById("raw-headers");
  modeInputs.forEach(function (input) {
    input.addEventListener("change", function () {
      var full = input.value === "headers_body" && input.checked;
      if (!input.checked) return;
      headersField.hidden = !full;
      headersInput.required = full;
      syncGate(forms[1]);
    });
  });

  function attestationsComplete(form) {
    return form.querySelector('[name="authorization_attested"]').checked && form.querySelector('[name="no_credentials_acknowledged"]').checked;
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

  async function submitForm(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!attestationsComplete(form)) {
      showError("Confirm both required attestations before submitting.");
      return;
    }
    if (form === forms[0]) showFile(fileInput.files[0]);
    if (!form.reportValidity()) return;
    if (form === forms[1]) {
      var bytes = new TextEncoder().encode((headersInput.value || "") + "\r\n\r\n" + document.getElementById("email-body").value).length;
      if (bytes > EMAIL_LIMIT) { showError("The pasted email exceeds the 10 MiB limit. Nothing was submitted."); return; }
    }

    var button = form.querySelector(".submit-button");
    button.disabled = true;
    button.textContent = "Submitting…";
    result.innerHTML = "<p>Submitting evidence to the configured API…</p>";
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });

    try {
      var options = { method: "POST", headers: { "Accept": "application/json" } };
      if (form === forms[0]) {
        options.body = new FormData(form);
      } else {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify({
          tenant_uid: form.elements.tenant_uid.value.trim(),
          authorization_attested: true,
          no_credentials_acknowledged: true,
          mode: form.elements.mode.value,
          raw_headers: form.elements.mode.value === "headers_body" ? headersInput.value : null,
          body: form.elements.body.value
        });
      }
      var response = await fetch(form.action, options);
      var payload = await safeJson(response);
      if (!response.ok) throw new Error(safeErrorMessage(response.status, payload));
      showSuccess(payload);
      form.reset();
      if (form === forms[0]) { dropZone.classList.remove("has-file"); fileFeedback.textContent = ""; }
      if (form === forms[1]) { headersField.hidden = false; headersInput.required = true; }
    } catch (error) {
      showError(error.message || "Submission failed. No sensitive response content is displayed.");
    } finally {
      button.textContent = form === forms[0] ? "Submit email file" : "Submit pasted email";
      syncGate(form);
    }
  }

  async function safeJson(response) {
    var type = response.headers.get("content-type") || "";
    if (!type.includes("application/json")) return null;
    try { return await response.json(); } catch (_error) { return null; }
  }

  function safeErrorMessage(status, payload) {
    var generic = {
      400: "The request was rejected. Confirm both attestations and try again.",
      404: "The tenant or intake endpoint was not found.",
      409: "The intake could not be persisted. Try again or contact an administrator.",
      413: "The evidence exceeds the allowed size limit.",
      422: "The evidence or request fields did not pass validation.",
      503: "The intake service is temporarily unavailable."
    }[status];
    if (generic) return generic + " Nothing from the submitted evidence is shown.";
    return "Submission failed (HTTP " + status + "). Nothing from the submitted evidence is shown.";
  }

  function safeValue(value) {
    return typeof value === "string" || typeof value === "number" ? String(value) : "Unavailable";
  }

  function showSuccess(payload) {
    result.replaceChildren();
    var heading = document.createElement("p");
    heading.className = "result-success";
    heading.textContent = "Evidence accepted";
    result.appendChild(heading);
    var note = document.createElement("p");
    note.textContent = "Only safe intake metadata is shown. Submitted content is never displayed here.";
    result.appendChild(note);
    var list = document.createElement("dl");
    list.className = "metadata";
    [["Job ID", payload && payload.job_id], ["Submission ID", payload && payload.submission_id], ["Source type", payload && payload.source_type], ["Fidelity", payload && payload.fidelity]].forEach(function (item) {
      var dt = document.createElement("dt"); dt.textContent = item[0];
      var dd = document.createElement("dd"); dd.textContent = safeValue(item[1]);
      list.appendChild(dt); list.appendChild(dd);
    });
    result.appendChild(list);
  }

  function showError(message) {
    result.replaceChildren();
    var heading = document.createElement("p");
    heading.className = "result-error";
    heading.textContent = "Submission not accepted";
    var note = document.createElement("p");
    note.textContent = message;
    result.appendChild(heading);
    result.appendChild(note);
    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}());
