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

})();
