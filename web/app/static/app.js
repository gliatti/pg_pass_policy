/* pgpp-web: copy / hide buttons of the one-time password display.
   Served as a static file: the CSP forbids inline scripts. */
(function () {
  "use strict";

  function selectText(el) {
    var range = document.createRange();
    range.selectNodeContents(el);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  document.addEventListener("click", function (ev) {
    var copy = ev.target.closest("[data-copy-target]");
    if (copy) {
      var src = document.getElementById(copy.getAttribute("data-copy-target"));
      if (!src) { return; }
      var done = function () {
        copy.textContent = "Copied";
        setTimeout(function () { copy.textContent = "Copy"; }, 2000);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(src.textContent).then(done, function () { selectText(src); });
      } else {
        selectText(src);
        try { document.execCommand("copy"); done(); } catch (e) { /* manual copy */ }
      }
      return;
    }
    var hide = ev.target.closest("[data-dismiss]");
    if (hide) {
      var box = document.getElementById(hide.getAttribute("data-dismiss"));
      if (box) { box.remove(); }
    }
  });

  // a revealed password never survives the next htmx swap elsewhere on the
  // page (beforeSwap, so that the password carried by the incoming response
  // itself is kept)
  document.addEventListener("htmx:beforeSwap", function (ev) {
    var target = ev.detail.target;
    document.querySelectorAll(".reveal").forEach(function (el) {
      if (!target || !target.contains(el)) { el.remove(); }
    });
  });

  // never let a revealed password survive a page unload in the DOM snapshot
  window.addEventListener("pagehide", function () {
    document.querySelectorAll(".reveal").forEach(function (el) { el.remove(); });
  });
})();
