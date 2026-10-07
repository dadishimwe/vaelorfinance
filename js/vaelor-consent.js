(function () {
  var MEASUREMENT_ID = "G-7VDGW720LJ";
  var STORAGE_KEY = "vaelor-consent";

  function choice() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return null;
    }
  }

  function remember(value) {
    try {
      localStorage.setItem(STORAGE_KEY, value);
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

  function apply(value) {
    remember(value);
    hideBanner();
    window.dispatchEvent(new CustomEvent("vaelor-consent", { detail: value }));
  }

  function showBanner() {
    if (document.getElementById("vaelor-consent")) return;
    var banner = document.createElement("div");
    banner.id = "vaelor-consent";
    banner.setAttribute("role", "dialog");
    banner.setAttribute("aria-label", "Cookie choices");
    banner.innerHTML =
      '<div class="vaelor-consent-card">' +
      '<p>Pages you open and your approximate location are recorded on every visit. Accept or Reject is saved for any further measurement. <a href="privacy.html">Privacy policy</a></p>' +
      '<div class="vaelor-consent-actions">' +
      '<button type="button" data-consent="rejected">Reject</button>' +
      '<button type="button" data-consent="accepted">Accept</button>' +
      "</div></div>";
    document.body.appendChild(banner);
    banner.addEventListener("click", function (event) {
      var button = event.target.closest("[data-consent]");
      if (!button) return;
      apply(button.getAttribute("data-consent"));
    });
  }

  window.vaelorConsent = choice;

  var style = document.createElement("style");
  style.textContent =
    "#vaelor-consent{position:fixed;left:16px;right:16px;bottom:16px;z-index:2000;display:flex;justify-content:center}" +
    ".vaelor-consent-card{width:min(720px,100%);background:#F4F0E8;color:#1c1416;border-radius:18px;padding:18px 18px 16px;box-shadow:0 12px 40px rgba(0,0,0,.28)}" +
    ".vaelor-consent-card p{margin:0 0 14px;font-family:Arial,sans-serif;font-size:15px;line-height:1.5}" +
    ".vaelor-consent-card a{color:#8a6420}" +
    ".vaelor-consent-actions{display:flex;justify-content:flex-end;gap:10px}" +
    ".vaelor-consent-actions button{font-family:\"Geist Mono\",ui-monospace,monospace;font-size:12px;letter-spacing:.08em;text-transform:uppercase;border-radius:999px;padding:10px 16px;cursor:pointer}" +
    ".vaelor-consent-actions [data-consent=rejected]{background:transparent;color:#1c1416;border:1px solid rgba(28,20,22,.35)}" +
    ".vaelor-consent-actions [data-consent=accepted]{background:#111;color:#f7f3ea;border:1px solid #111}" +
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

  if (choice() !== "accepted" && choice() !== "rejected") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", showBanner);
    } else showBanner();
  }
})();
