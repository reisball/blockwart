(() => {
  const root = document.documentElement;
  const storageKey = "blockwart-theme";

  function normalizeTheme(theme) {
    return theme === "light" ? "light" : "dark";
  }

  function applyTheme(theme) {
    const normalizedTheme = normalizeTheme(theme);
    if (normalizedTheme === "light") {
      root.dataset.theme = "light";
    } else {
      root.removeAttribute("data-theme");
    }
    localStorage.setItem(storageKey, normalizedTheme);
    document.querySelectorAll("[data-theme-value]").forEach((button) => {
      button.setAttribute(
        "aria-pressed",
        button.dataset.themeValue === normalizedTheme ? "true" : "false",
      );
    });
  }

  document.querySelectorAll("[data-theme-value]").forEach((button) => {
    button.addEventListener("click", () => applyTheme(button.dataset.themeValue));
  });

  applyTheme(localStorage.getItem(storageKey));
})();
