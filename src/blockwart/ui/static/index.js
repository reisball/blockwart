(() => {
  const cards = Array.from(document.querySelectorAll("[data-object-card]"));
  const createKindSelect = document.querySelector("[data-kind-select]");
  const platformField = document.querySelector("[data-platform-field]");
  const primaryNameLabel = document.querySelector("[data-primary-name-label]");
  const createFields = Array.from(document.querySelectorAll("[data-create-field]"));
  const uiSchemas = window.BLOCKWART_UI_SCHEMAS || {};

  function closeCard(card) {
    card.classList.remove("is-expanded");
    card.querySelector("[data-object-toggle]")?.setAttribute("aria-expanded", "false");
    closeRelationshipDetails(card);
  }

  function closeAll(except = null) {
    for (const card of cards) {
      if (card !== except) {
        closeCard(card);
      }
    }
  }

  function toggleCard(card) {
    const isExpanded = card.classList.contains("is-expanded");
    closeAll(card);
    if (isExpanded) {
      closeCard(card);
      return;
    }
    card.classList.add("is-expanded");
    card.querySelector("[data-object-toggle]")?.setAttribute("aria-expanded", "true");
  }

  function closeRelationshipDetails(card) {
    for (const node of card.querySelectorAll("[data-relationship-node]")) {
      node.classList.remove("is-selected");
      node.setAttribute("aria-expanded", "false");
    }
    for (const panel of card.querySelectorAll("[data-relationship-detail-panel]")) {
      panel.classList.remove("is-open");
    }
  }

  function openRelationshipDetail(card, node) {
    const targetId = node.getAttribute("data-detail-target");
    const panel = targetId ? card.querySelector(`#${CSS.escape(targetId)}`) : null;
    if (!panel) {
      return;
    }
    closeRelationshipDetails(card);
    node.classList.add("is-selected");
    node.setAttribute("aria-expanded", "true");
    panel.classList.add("is-open");
  }

  for (const card of cards) {
    const toggle = card.querySelector("[data-object-toggle]");
    for (const detailLink of card.querySelectorAll("[data-detail-link]")) {
      detailLink.addEventListener("click", (event) => event.stopPropagation());
    }
    for (const relationshipNode of card.querySelectorAll("[data-relationship-node]")) {
      relationshipNode.setAttribute("aria-expanded", "false");
      relationshipNode.addEventListener("click", (event) => {
        event.stopPropagation();
        openRelationshipDetail(card, relationshipNode);
      });
      relationshipNode.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") {
          return;
        }
        event.preventDefault();
        openRelationshipDetail(card, relationshipNode);
      });
    }
    toggle?.addEventListener("click", () => toggleCard(card));
    toggle?.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      event.preventDefault();
      toggleCard(card);
    });
  }

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    if (target.closest("[data-object-card]")) {
      const card = target.closest("[data-object-card]");
      if (!target.closest("[data-relationship-detail-panel]")) {
        closeRelationshipDetails(card);
      }
      return;
    }
    closeAll();
  });

  function setFieldEnabled(field, enabled) {
    field.hidden = !enabled;
    for (const input of field.querySelectorAll("input, select, textarea")) {
      input.disabled = !enabled;
    }
  }

  function updateCreateFields() {
    if (!createKindSelect) {
      return;
    }
    const schema = uiSchemas[createKindSelect.value] || {};
    const allowedFields = new Set(schema.create_fields || []);
    const fieldDefinitions = new Map(
      (schema.create_field_definitions || []).map((field) => [field.key, field])
    );
    if (primaryNameLabel && schema.primary_name_label) {
      primaryNameLabel.textContent = schema.primary_name_label;
    }
    for (const field of createFields) {
      const key = field.getAttribute("data-create-field");
      setFieldEnabled(field, !key || allowedFields.has(key));
      const definition = key ? fieldDefinitions.get(key) : null;
      const label = key
        ? field.querySelector('[data-field-label="' + CSS.escape(key) + '"]')
        : null;
      const input = key
        ? field.querySelector('[data-field-input="' + CSS.escape(key) + '"]')
        : null;
      if (label && definition?.label) {
        label.textContent = definition.label;
      }
      if (input && definition) {
        input.placeholder = definition.placeholder || "";
        input.required = Boolean(definition.required);
      }
    }
    if (platformField) {
      platformField.hidden = !allowedFields.has("platform");
    }
  }

  createKindSelect?.addEventListener("change", updateCreateFields);
  updateCreateFields();
})();
