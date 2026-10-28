(() => {
  const editableFields = (row) =>
    Array.from(row.querySelectorAll("input:not([type='hidden']), select, textarea"));

  const rowHasValue = (row) =>
    editableFields(row).some((field) => {
      const value = String(field.value || "").trim();
      return value && value !== field.dataset.emptyValue;
    });

  const updateRequiredFields = (row) => {
    const required = rowHasValue(row);
    row.querySelectorAll("[data-required-when-row-filled]").forEach((field) => {
      field.required = required;
    });
  };

  const prepareRow = (row) => {
    editableFields(row).forEach((field) => {
      field.addEventListener("input", () => updateRequiredFields(row));
      field.addEventListener("change", () => updateRequiredFields(row));
    });
    updateRequiredFields(row);
  };

  document.querySelectorAll("[data-row-list] > tr").forEach(prepareRow);

  document.querySelectorAll("[data-add-row]").forEach((button) => {
    button.addEventListener("click", () => {
      const group = button.dataset.addRow;
      const list = document.querySelector(`[data-row-list="${group}"]`);
      const template = document.querySelector(`[data-row-template="${group}"]`);
      const row = template?.content.firstElementChild?.cloneNode(true);
      if (!list || !row) {
        return;
      }

      if (group === "access-methods") {
        const ref = row.querySelector("[name='method_ref']")?.value;
        const indexInput = row.querySelector("[name='method_index']");
        const indexes = Array.from(
          list.querySelectorAll("[name='method_index']"),
        )
          .filter(
            (candidate) =>
              candidate
                .closest("tr")
                ?.querySelector("[name='method_ref']")
                ?.value === ref,
          )
          .map((candidate) => Number.parseInt(candidate.value, 10))
          .filter(Number.isInteger);
        if (indexInput) {
          indexInput.value = String(
            indexes.length ? Math.max(...indexes) + 1 : Number(indexInput.value || 0),
          );
        }
      }

      list.append(row);
      prepareRow(row);
      editableFields(row)[0]?.focus();
    });
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove-row]");
    if (!button) {
      return;
    }
    button.closest("tr")?.remove();
  });

  document.querySelectorAll("[data-grant-form]").forEach((form) => {
    const role = form.querySelector("[name='role'], [data-grant-role]");
    const scope = form.querySelector("[name='scope'], [data-grant-scope]");
    if (!role || !scope) return;
    const responsibility = scope.querySelector("[value='responsibility']");
    const updateScope = (changedRole = false) => {
      const eligible = form.dataset.responsibilityEligible === "true" && role.value === "owner";
      if (responsibility) responsibility.disabled = !eligible;
      if (!eligible && scope.value === "responsibility") scope.value = "self";
      if (eligible && changedRole && form.hasAttribute("data-grant-new")) {
        scope.value = "responsibility";
      }
    };
    role.addEventListener("change", () => updateScope(true));
    updateScope();
    form.querySelector("[data-preview-grant]")?.addEventListener("click", () => {
      const url = new URL(window.location.href);
      url.searchParams.set("edit", "permissions");
      url.searchParams.set("preview_role", role.value);
      url.searchParams.set("preview_scope", scope.value);
      // Never serialize a mutation form: it contains private CSRF state.
      window.location.assign(url.toString());
    });
  });

})();
