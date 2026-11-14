// Local templates only: never fetch or pre-load a secret value.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-safe-preset]").forEach((select) => {
    select.addEventListener("change", () => {
      const field = select.form.querySelector("[name=fields_json]");
      if (!field || field.value.trim()) return;
      const presets = {
        login: {username: "", password: ""},
        token: {token: ""},
        key: {key: "", passphrase: ""},
        other: {value: ""}
      };
      field.value = JSON.stringify(presets[select.value], null, 2);
    });
  });
});
