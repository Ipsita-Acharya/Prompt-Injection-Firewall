/* Injected into every UI replica page. Wires the page's OWN prompt box, send button
 * and attach button to the PIL API (POST /pif/scan) and shows a bottom-right
 * verdict toast. No extra prompt composer is added. */
(function () {
  "use strict";

  var MAX_FILE_BYTES = 10 * 1024 * 1024;

  var COLORS = {
    green: { bg: "#16a34a", bar: "#0e7a37" },
    red: { bg: "#dc2626", bar: "#9f1d1d" },
    orange: { bg: "#ea8a0a", bar: "#b56a05" },
  };

  /* ---------- verdict toast ---------- */
  var toastHost = document.createElement("div");
  toastHost.style.cssText =
    "position:fixed;right:20px;bottom:20px;z-index:2147483647;display:flex;" +
    "flex-direction:column;gap:10px;width:360px;max-width:calc(100vw - 40px);";
  document.body.appendChild(toastHost);

  function showToast(kind, title, details) {
    var color = COLORS[kind] || COLORS.orange;
    var toast = document.createElement("div");
    toast.style.cssText =
      "background:" + color.bg + ";color:#fff;border-radius:10px;overflow:hidden;" +
      "box-shadow:0 8px 24px rgba(0,0,0,.45);font-family:'Segoe UI',Arial,sans-serif;";
    var head = document.createElement("div");
    head.style.cssText =
      "display:flex;align-items:center;justify-content:space-between;padding:12px 14px;" +
      "border-bottom:1px solid " + color.bar + ";";
    var label = document.createElement("strong");
    label.textContent = title;
    label.style.fontSize = "15px";
    var close = document.createElement("button");
    close.textContent = "\u00d7";
    close.style.cssText =
      "background:none;border:none;color:#fff;font-size:18px;cursor:pointer;line-height:1;padding:0 2px;";
    close.onclick = function () {
      toast.remove();
    };
    head.appendChild(label);
    head.appendChild(close);
    toast.appendChild(head);
    if (details) {
      var body = document.createElement("div");
      body.style.cssText = "padding:10px 14px 12px;font-size:12.5px;line-height:1.5;white-space:pre-wrap;";
      body.textContent = details;
      toast.appendChild(body);
    }
    toastHost.appendChild(toast);
    var ttl = kind === "green" ? 7000 : 15000;
    setTimeout(function () {
      toast.remove();
    }, ttl);
  }

  function formatDetails(result, httpStatus) {
    if (!result) return "HTTP " + httpStatus + ": no parseable body from the PIF API.";
    var lines = [];
    lines.push("Decision: " + result.decision);
    lines.push("Status: " + result.status + "  |  Risk: " + result.risk_level +
      (result.risk != null ? " (" + result.risk + ")" : ""));
    if (result.attacks && result.attacks.length) {
      lines.push("Attacks: " + result.attacks.join(", "));
    }
    if (result.findings && result.findings.length) {
      lines.push("Findings: " + result.findings.length + " (" +
        result.findings.map(function (f) { return f.category; }).join(", ") + ")");
    }
    if (result.quarantined && result.quarantined.length) {
      lines.push("Quarantined: " + result.quarantined.join(", "));
    }
    if (result.warnings && result.warnings.length) {
      lines.push("Warnings: " + result.warnings.join("; "));
    }
    if (result.scan_id) lines.push("Scan ID: " + result.scan_id);
    return lines.join("\n");
  }

  function reportError(message) {
    showToast("orange", "PIF Error", message);
  }

  /* ---------- attachments (shared hidden file input + a small pill listing picks) ---------- */
  var fileInput = document.createElement("input");
  fileInput.type = "file";
  fileInput.id = "pif-file-input";
  fileInput.multiple = true;
  fileInput.style.display = "none";
  document.body.appendChild(fileInput);

  var pill = document.createElement("div");
  pill.style.cssText =
    "position:fixed;left:50%;transform:translateX(-50%);bottom:16px;z-index:2147483645;display:none;" +
    "background:#24272e;color:#e8eaed;border:1px solid #3c4048;border-radius:10px;padding:6px 10px;" +
    "font:12.5px 'Segoe UI',Arial,sans-serif;box-shadow:0 6px 18px rgba(0,0,0,.4);" +
    "max-width:min(720px,92vw);";
  document.body.appendChild(pill);

  function renderPill() {
    var files = Array.prototype.slice.call(fileInput.files);
    if (!files.length) {
      pill.style.display = "none";
      return;
    }
    pill.textContent = "";
    files.forEach(function (file) {
      var chip = document.createElement("span");
      chip.style.cssText =
        "display:inline-block;background:#2f333c;border:1px solid #3c4048;border-radius:8px;" +
        "padding:2px 8px;margin:2px 4px 2px 0;";
      chip.textContent = "\ud83d\udcce " + file.name + " (" + Math.ceil(file.size / 1024) + " KB)";
      pill.appendChild(chip);
    });
    var clear = document.createElement("button");
    clear.textContent = "\u00d7 Clear";
    clear.style.cssText =
      "background:none;border:none;color:#9aa0a6;cursor:pointer;font:12px 'Segoe UI',Arial,sans-serif;";
    clear.onclick = function () {
      fileInput.value = "";
      renderPill();
    };
    pill.appendChild(clear);
    pill.style.display = "block";
  }
  fileInput.onchange = renderPill;

  /* ---------- locate the page's own composer ---------- */
  function findComposer() {
    var el = document.querySelector("#mobile-composer-prompt"); // ChatGPT saved page
    if (el) return { el: el, kind: "textarea" };
    el = document.querySelector(".ql-editor[aria-label]"); // Gemini saved page
    if (el) return { el: el, kind: "editor" };
    el = document.querySelector(".input-box input[type=text]"); // GenWizard saved page
    if (el) return { el: el, kind: "input" };
    return null;
  }

  function readValue(composer) {
    if (composer.kind === "editor") return composer.el.innerText.trim();
    return composer.el.value.trim();
  }

  function clearValue(composer) {
    if (composer.kind === "editor") {
      composer.el.innerHTML = "<p><br></p>";
      composer.el.classList.add("ql-blank");
      return;
    }
    composer.el.value = "";
    composer.el.dispatchEvent(new Event("input", { bubbles: true }));
  }

  /* ---------- send ---------- */
  var busy = false;

  function readFileAsBase64(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        resolve(String(reader.result).split(",", 2)[1] || "");
      };
      reader.onerror = function () {
        reject(new Error("Could not read " + file.name));
      };
      reader.readAsDataURL(file);
    });
  }

  function send() {
    if (busy) return;
    var composer = findComposer();
    if (!composer) return;
    var prompt = readValue(composer);
    var files = Array.prototype.slice.call(fileInput.files);
    if (!prompt && files.length === 0) return;
    for (var i = 0; i < files.length; i++) {
      if (files[i].size > MAX_FILE_BYTES) {
        reportError("File too large: " + files[i].name + " exceeds 10 MiB.");
        return;
      }
    }
    busy = true;
    Promise.all(files.map(readFileAsBase64))
      .then(function (payloads) {
        return fetch("/pif/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            prompt: prompt,
            files: files.map(function (file, index) {
              return {
                name: file.name,
                type: file.type || "application/octet-stream",
                data_base64: payloads[index],
              };
            }),
          }),
        });
      })
      .then(function (response) {
        return response.json().then(function (data) {
          return { data: data, httpStatus: response.status };
        });
      })
      .then(function (outcome) {
        var data = outcome.data || {};
        if (!data.ok) {
          reportError(data.error || formatDetails(data.result, outcome.httpStatus));
          return;
        }
        var result = data.result || {};
        var details = formatDetails(result, outcome.httpStatus);
        if (result.decision === "allow" && result.malicious === false) {
          showToast("green", "PIF Verified", details);
        } else if (result.decision === "block" || result.malicious === true) {
          showToast("red", "PIF Blocked", details);
        } else {
          showToast("orange", "PIF " + String(result.decision || result.status || "Unknown").toUpperCase(), details);
        }
        clearValue(composer);
        fileInput.value = "";
        renderPill();
      })
      .catch(function (error) {
        reportError("Request failed: " + (error && error.message ? error.message : error));
      })
      .then(function () {
        busy = false;
      });
  }

  /* ---------- wire the existing controls ---------- */
  function wire() {
    var composer = findComposer();
    if (!composer) return;

    // The saved Gemini page never toggles its "ql-blank" placeholder class while the
    // user types, so the placeholder overlaps the typed text — keep it in sync.
    if (composer.kind === "editor") {
      composer.el.addEventListener("input", function () {
        composer.el.classList.toggle("ql-blank", composer.el.innerText.trim() === "");
      });
    }

    composer.el.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        send();
      }
    });

    // Existing send button: ChatGPT has aria-label="Send message"; GenWizard's arrow
    // button sits next to the input. The Gemini snapshot contains no send button at
    // all (the live site renders it only while typing), so one is added next to its
    // microphone button.
    var sendBtn = document.querySelector('button[aria-label="Send message"]');
    if (!sendBtn && composer.kind === "input") {
      var node = composer.el;
      for (var up = 0; up < 4 && node && !sendBtn; up++) {
        node = node.parentElement;
        if (node) sendBtn = node.querySelector("button");
      }
    }
    if (!sendBtn && composer.kind === "editor") {
      sendBtn = document.createElement("button");
      sendBtn.type = "button";
      sendBtn.title = "Send";
      sendBtn.innerHTML =
        '<svg viewBox="0 0 24 24" width="20" height="20" fill="none">' +
        '<path d="M12 4v12m0 0 5-5m-5 5-5-5" stroke="#fff" stroke-width="2.2" ' +
        'stroke-linecap="round" stroke-linejoin="round"/></svg>';
      sendBtn.style.cssText =
        "width:36px;height:36px;border-radius:50%;border:none;cursor:pointer;" +
        "display:flex;align-items:center;justify-content:center;background:#1f6feb;" +
        "box-shadow:0 1px 4px rgba(0,0,0,.4);flex:0 0 auto;";
      // place it as a sibling of the microphone inside the composer's trailing
      // actions (inserting next to the mic's inner button lands in a hidden node)
      var mic = document.querySelector('button [data-mat-icon-name="mic"], button[data-mat-icon-name="mic"]');
      var trailing = mic && (mic.closest('[class*="trailing-actions"]') || mic.closest('[class*="trailing"]'));
      if (mic && trailing) {
        var anchor = mic;
        while (anchor.parentElement && anchor.parentElement !== trailing) {
          anchor = anchor.parentElement;
        }
        trailing.insertBefore(sendBtn, anchor);
      } else {
        var host = composer.el.closest(".input-area") || composer.el.parentElement;
        host.appendChild(sendBtn);
      }
    }
    if (sendBtn) {
      // The saved pages' own scripts can re-disable the button after boot; keep it usable.
      var keepEnabled = function () {
        if (sendBtn.disabled) {
          sendBtn.disabled = false;
          sendBtn.classList.remove("Mui-disabled");
        }
      };
      keepEnabled();
      setInterval(keepEnabled, 1500);
      sendBtn.addEventListener("click", function (event) {
        event.preventDefault();
        send();
      });
    }

    // Existing attach button(s): ChatGPT "Add files…" / Gemini "Upload & tools".
    // If the page has none (GenWizard home), add one beside its input.
    var attachSelectors = [
      'button[aria-label="Add files and more"]',
      'button[aria-label="Add attachment actions"]',
      'button[aria-label^="Add files"]',
      'gem-icon-button[arialabel="Upload & tools"] button',
      'gem-icon-button[arialabel="Upload & tools"]',
    ];
    var attachBtn = null;
    for (var s = 0; s < attachSelectors.length && !attachBtn; s++) {
      attachBtn = document.querySelector(attachSelectors[s]);
    }
    if (!attachBtn) {
      attachBtn = document.createElement("button");
      attachBtn.type = "button";
      attachBtn.title = "Attach files";
      attachBtn.textContent = "\ud83d\udcce";
      attachBtn.className = "pif-attach";
      var host = composer.el.closest(".MuiInputBase-root") || composer.el.parentElement;
      host.insertBefore(attachBtn, host.firstChild);
    }
    attachBtn.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();
      fileInput.click();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
