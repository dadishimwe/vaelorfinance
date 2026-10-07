(function () {
  var MEASUREMENT_ID = "G-7VDGW720LJ";
  var STORAGE_KEY = "vaelor-notice";

  function dismissed() {
    try {
      return localStorage.getItem(STORAGE_KEY) === "dismissed";
    } catch (e) {
      return false;
    }
  }

  function rememberDismissed() {
    try {
      localStorage.setItem(STORAGE_KEY, "dismissed");
    } catch (e) {}
  }

  function loadAnalytics() {
    if (window.__vaelorGA) return;
    window.__vaelorGA = true;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () {
      window.dataLayer.push(arguments);
    };
    window.gtag("js", new Date());
    window.gtag("config", MEASUREMENT_ID);
    var script = document.createElement("script");
    script.async = true;
    script.src = "https://www.googletagmanager.com/gtag/js?id=" + MEASUREMENT_ID;
    document.head.appendChild(script);
  }

  function hideBanner() {
    var banner = document.getElementById("vaelor-consent");
    if (banner) banner.remove();
  }

  function showBanner() {
    if (document.getElementById("vaelor-consent")) return;
    var banner = document.createElement("div");
    banner.id = "vaelor-consent";
    banner.setAttribute("role", "dialog");
    banner.setAttribute("aria-label", "Site measurement");
    banner.innerHTML =
      '<div class="vaelor-consent-card">' +
      '<p>Pages you open and your approximate location are recorded on every visit. <a href="privacy.html">Privacy policy</a></p>' +
      '<div class="vaelor-consent-actions">' +
      '<button type="button" data-notice-close>Close</button>' +
      "</div></div>";
    document.body.appendChild(banner);
    banner.addEventListener("click", function (event) {
      if (!event.target.closest("[data-notice-close]")) return;
      rememberDismissed();
      hideBanner();
    });
  }

  var style = document.createElement("style");
  style.textContent =
    "#vaelor-consent{position:fixed;left:16px;right:16px;bottom:16px;z-index:2000;display:flex;justify-content:center}" +
    ".vaelor-consent-card{width:min(720px,100%);background:#F4F0E8;color:#1c1416;border-radius:18px;padding:18px 18px 16px;box-shadow:0 12px 40px rgba(0,0,0,.28)}" +
    ".vaelor-consent-card p{margin:0 0 14px;font-family:Arial,sans-serif;font-size:15px;line-height:1.5}" +
    ".vaelor-consent-card a{color:#8a6420}" +
    ".vaelor-consent-actions{display:flex;justify-content:flex-end;gap:10px}" +
    ".vaelor-consent-actions button{font-family:\"Geist Mono\",ui-monospace,monospace;font-size:12px;letter-spacing:.08em;text-transform:uppercase;border-radius:999px;padding:10px 16px;cursor:pointer;background:#111;color:#f7f3ea;border:1px solid #111}" +
    ".vaelor-cookie-settings{background:none;border:0;padding:0;cursor:pointer;font:inherit;color:inherit;text-align:left}" +
    "@media (max-width:640px){.vaelor-consent-actions{flex-direction:column}.vaelor-consent-actions button{width:100%}}";
  document.head.appendChild(style);

  document.addEventListener("click", function (event) {
    var opener = event.target.closest("[data-cookie-settings]");
    if (!opener) return;
    event.preventDefault();
    showBanner();
  });

  loadAnalytics();

  if (!dismissed()) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", showBanner);
    } else showBanner();
  }
})();
