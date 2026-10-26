// Applies the saved color scheme before React mounts, so a light-theme user does not see a dark flash.
(function () {
  try {
    var v = window.localStorage.getItem("sentinel-color-scheme");
    if (v === "light" || v === "dark") document.documentElement.setAttribute("data-mantine-color-scheme", v);
  } catch (e) {
    /* storage blocked: keep the dark default */
  }
})();
