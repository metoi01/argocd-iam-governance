// Small progressive enhancements; every page works without JavaScript.
(function () {
  "use strict";

  function fmt(seconds) {
    seconds = Math.max(0, seconds);
    var h = Math.floor(seconds / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var s = seconds % 60;
    var pad = function (n) { return (n < 10 ? "0" : "") + n; };
    return h ? h + "h " + pad(m) + "m" : m + "m " + pad(s) + "s";
  }

  document.addEventListener("DOMContentLoaded", function () {
    // Live countdown for temporary grants; reload when one expires so the
    // page reflects the restored role.
    var timers = document.querySelectorAll("[data-expires]");
    if (timers.length) {
      var started = Date.now();
      setInterval(function () {
        var elapsed = Math.floor((Date.now() - started) / 1000);
        timers.forEach(function (el) {
          var left = parseInt(el.getAttribute("data-expires"), 10) - elapsed;
          el.textContent = fmt(left);
          if (left <= 0 && !el.dataset.reloaded) {
            el.dataset.reloaded = "1";
            setTimeout(function () { window.location.reload(); }, 1500);
          }
        });
      }, 1000);
    }

    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.getAttribute("data-confirm"))) event.preventDefault();
      });
    });

    document.querySelectorAll("select[data-autosubmit]").forEach(function (select) {
      select.addEventListener("change", function () { select.form.submit(); });
    });
  });
})();
