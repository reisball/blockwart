(() => {
  const assets = window.BLOCKWART_EXPLORER_ASSETS || {};
  const kindLabels = window.BLOCKWART_KIND_LABELS || {};
  const copy = window.BLOCKWART_UI_COPY || {};
  const uiSchemas = window.BLOCKWART_UI_SCHEMAS || {};
  const selectableNodes = Array.from(document.querySelectorAll("[data-asset-ref]"));

  function setInspectorValue(root, selector, value) {
    const target = root.querySelector(selector);
    if (target) {
      target.textContent = value || copy.noValue || "—";
    }
  }

  function updateHealth(root, health) {
    const target = root.querySelector("[data-inspector-health]");
    if (!target) {
      return;
    }
    const normalizedHealth = health || "unknown";
    const badge = document.createElement("span");
    const dot = document.createElement("i");
    badge.className = `state-badge state-${normalizedHealth}`;
    badge.append(dot, document.createTextNode(
      copy.health?.[normalizedHealth] || normalizedHealth,
    ));
    target.replaceChildren(badge);
  }

  function updateInspector(root, asset) {
    if (!root || !asset) {
      return;
    }
    setInspectorValue(root, "[data-inspector-kind]", kindLabels[asset.kind] || asset.kind);
    setInspectorValue(root, "[data-inspector-title]", asset.label);
    setInspectorValue(root, "[data-inspector-summary]", asset.summary);
    setInspectorValue(root, "[data-inspector-address]", asset.address);
    setInspectorValue(root, "[data-inspector-platform]", asset.platform);
    setInspectorValue(root, "[data-inspector-lifecycle]", asset.lifecycle || asset.status);
    setInspectorValue(root, "[data-inspector-endpoint]", asset.endpoint);
    setInspectorValue(root, "[data-inspector-ref]", asset.ref);
    updateHealth(root, asset.health);
    const detailsLink = root.querySelector("[data-inspector-details]");
    if (detailsLink) {
      detailsLink.href = `/objects/${encodeURIComponent(asset.id)}`;
    }
  }

  function selectAsset(ref) {
    const asset = assets[ref];
    if (!asset) {
      return;
    }
    for (const node of selectableNodes) {
      node.classList.toggle("selected", node.dataset.assetRef === ref);
    }
    for (const inspector of document.querySelectorAll("[data-inspector]")) {
      updateInspector(inspector, asset);
    }
  }

  for (const node of selectableNodes) {
    node.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        return;
      }
      selectAsset(node.dataset.assetRef);
    });
    if (node.tagName !== "BUTTON") {
      node.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") {
          return;
        }
        event.preventDefault();
        selectAsset(node.dataset.assetRef);
      });
    }
  }

  const initiallySelected = selectableNodes.find((node) => (
    node.classList.contains("selected") && assets[node.dataset.assetRef]
  )) || selectableNodes.find((node) => assets[node.dataset.assetRef]);
  if (initiallySelected) {
    selectAsset(initiallySelected.dataset.assetRef);
  }

  const searchInput = document.querySelector('.top-search input[type="search"]');
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      searchInput?.focus();
    }
  });

  const createKindSelect = document.querySelector("[data-kind-select]");
  const platformField = document.querySelector("[data-platform-field]");
  const primaryNameLabel = document.querySelector("[data-primary-name-label]");
  const createFields = Array.from(document.querySelectorAll("[data-create-field]"));

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
      (schema.create_field_definitions || []).map((field) => [field.key, field]),
    );
    if (primaryNameLabel && schema.primary_name_label) {
      primaryNameLabel.textContent = schema.primary_name_label;
    }
    for (const field of createFields) {
      const key = field.getAttribute("data-create-field");
      setFieldEnabled(field, !key || allowedFields.has(key));
      const definition = key ? fieldDefinitions.get(key) : null;
      const label = key
        ? field.querySelector(`[data-field-label="${CSS.escape(key)}"]`)
        : null;
      const input = key
        ? field.querySelector(`[data-field-input="${CSS.escape(key)}"]`)
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
