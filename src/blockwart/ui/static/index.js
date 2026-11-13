(() => {
  const assets = window.BLOCKWART_EXPLORER_ASSETS || {};
  const kindLabels = window.BLOCKWART_KIND_LABELS || {};
  const copy = window.BLOCKWART_UI_COPY || {};
  const uiSchemas = window.BLOCKWART_UI_SCHEMAS || {};
  const explorerContext = window.BLOCKWART_EXPLORER_CONTEXT || {};
  const detailQuery = window.BLOCKWART_DETAIL_QUERY || "";
  const selectableNodes = Array.from(document.querySelectorAll("[data-asset-ref]"));
  const stateStoragePrefix = "blockwart-explorer-state:" + explorerContext.principalScope + ":";
  let selectedAssetRef = "";

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
    const lifecycle = asset.lifecycle
      ? (copy.lifecycle?.[asset.lifecycle] || asset.lifecycle)
      : (copy.status?.[asset.status] || asset.status);
    setInspectorValue(root, "[data-inspector-lifecycle]", lifecycle);
    setInspectorValue(root, "[data-inspector-endpoint]", asset.endpoint);
    setInspectorValue(root, "[data-inspector-ref]", asset.ref);
    updateHealth(root, asset.health);
    const detailsLink = root.querySelector("[data-inspector-details]");
    if (detailsLink) {
      detailsLink.href = `/objects/${encodeURIComponent(asset.id)}?${detailQuery}`;
    }
  }

  function selectAsset(ref) {
    const asset = assets[ref];
    if (!asset) {
      return;
    }
    selectedAssetRef = ref;
    for (const node of selectableNodes) {
      node.classList.toggle("selected", node.dataset.assetRef === ref);
    }
    for (const inspector of document.querySelectorAll("[data-inspector]")) {
      updateInspector(inspector, asset);
    }
  }

  for (const node of selectableNodes) {
    node.addEventListener("click", (event) => {
      const interactiveTarget = event.target.closest("a, button");
      if (interactiveTarget && interactiveTarget !== node) {
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

  const treeRows = Array.from(document.querySelectorAll("[data-tree-row]"));
  const treeNodes = new Map(
    Array.from(document.querySelectorAll("[data-tree-node]")).map((node) => [
      node.dataset.treeNode,
      node,
    ]),
  );
  const treeExpanded = new Map(
    Array.from(treeNodes.keys()).map((treeNode) => [treeNode, false]),
  );
  const treeChildLevels = new Map(Array.from(treeNodes.keys()).map(key => [key, 0]));
  const treeToggles = Array.from(document.querySelectorAll("[data-tree-toggle]"));
  const treeLevelButtons = Array.from(document.querySelectorAll("[data-tree-level]"));
  let maximumTreeDepth = 0;
  let manualTreeMode = false;

  function treeNodeIsExpanded(treeNode) {
    return treeExpanded.get(treeNode) === true;
  }

  function treeRowIsVisible(row) {
    if (Number(row.dataset.treeDepth) > (treeChildLevels.get(row.dataset.treeParent) ?? maximumTreeDepth)) {
      return false;
    }
    let parent = row.dataset.treeParent;
    while (parent) {
      if (!treeNodeIsExpanded(parent)) {
        return false;
      }
      parent = treeNodes.get(parent)?.dataset.treeParent;
    }
    return true;
  }

  function updateTreeToggle(toggle) {
    const treeNode = toggle.dataset.treeTarget;
    const node = treeNodes.get(treeNode);
    const expanded = treeNodeIsExpanded(treeNode);
    const label = node?.dataset.treeLabel || "";
    toggle.setAttribute("aria-expanded", String(expanded));
    toggle.setAttribute(
      "aria-label",
      ((expanded ? copy.tree?.collapse : copy.tree?.expand) || "{label}")
        .replace("{label}", label),
    );
  }

  function applyTreeState() {
    for (const row of treeRows) {
      row.hidden = !treeRowIsVisible(row);
    }
    const visibleRows = document.querySelectorAll("tr[data-asset-ref]:not([hidden])").length;
    for (const toggle of treeToggles) {
      updateTreeToggle(toggle);
    }
    for (const button of treeLevelButtons) {
      const active = Number(button.dataset.treeLevel) === maximumTreeDepth && !manualTreeMode;
      button.classList.toggle("active", active);
      button.setAttribute("aria-checked", String(active));
      button.tabIndex = active || (manualTreeMode && button === treeLevelButtons[0]) ? 0 : -1;
    }
    updateVisibleRowCount(visibleRows);
  }

  function updateVisibleRowCount(visibleRows) {
    const counter = document.querySelector("[data-visible-row-count]");
    if (counter) {
      counter.textContent = String(visibleRows);
    }
    const label = document.querySelector("[data-visible-row-label]");
    if (label) {
      label.setAttribute(
        "aria-label",
        (copy.visibleRows || "{visible} rows visible").replace("{visible}", String(visibleRows)),
      );
    }
  }

  function setManualMode(isManual) {
    manualTreeMode = isManual;
    const marker = document.querySelector("[data-tree-manual]");
    if (marker) {
      marker.hidden = !isManual;
    }
  }

  function setTreeLevel(level) {
    maximumTreeDepth = level;
    manualTreeMode = false;
    for (const [treeNode, node] of treeNodes) {
      treeExpanded.set(treeNode, Number(node.dataset.treeDepth) < level);
      treeChildLevels.set(treeNode, level);
    }
    const marker = document.querySelector("[data-tree-manual]");
    if (marker) {
      marker.hidden = true;
    }
    applyTreeState();
  }

  for (const toggle of treeToggles) {
    toggle.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const treeNode = toggle.dataset.treeTarget;
      const opening = !treeNodeIsExpanded(treeNode);
      treeExpanded.set(treeNode, opening);
      if (opening) treeChildLevels.set(treeNode, 2);
      setManualMode(true);
      applyTreeState();
    });
  }
  for (const button of treeLevelButtons) {
    button.addEventListener("click", () => setTreeLevel(Number(button.dataset.treeLevel)));
    button.addEventListener("keydown", (event) => {
      const keys = ["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp", "Home", "End"];
      if (!keys.includes(event.key)) {
        return;
      }
      event.preventDefault();
      const current = treeLevelButtons.findIndex(
        (candidate) => candidate.classList.contains("active"),
      );
      let next = current;
      if (event.key === "Home") {
        next = 0;
      } else if (event.key === "End") {
        next = treeLevelButtons.length - 1;
      } else {
        const step = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : -1;
        next = Math.max(0, Math.min(treeLevelButtons.length - 1, current + step));
      }
      treeLevelButtons[next].focus();
      setTreeLevel(Number(treeLevelButtons[next].dataset.treeLevel));
    });
  }
  if (treeNodes.size) {
    setTreeLevel(0);
  } else {
    updateVisibleRowCount(document.querySelectorAll("tr[data-asset-ref]:not([hidden])").length);
  }

  function readStoredState(token) {
    if (!token || !/^[A-Za-z0-9_-]{12,64}$/.test(token)) {
      return null;
    }
    try {
      const parsed = JSON.parse(sessionStorage.getItem(`${stateStoragePrefix}${token}`) || "null");
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch {
      return null;
    }
  }

  function stateToken() {
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID().replaceAll("-", "");
    }
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  }

  function captureExplorerState(trigger) {
    const triggerAsset = trigger.closest("[data-asset-ref]")?.dataset.assetRef
      || selectedAssetRef
      || explorerContext.selectedRef
      || "";
    if (triggerAsset && assets[triggerAsset]) {
      selectAsset(triggerAsset);
    }
    const token = stateToken();
    const mainScroll = document.querySelector("[data-main-scroll]");
    const state = {
      version: 1,
      view: explorerContext.view || "catalog",
      query: explorerContext.query || "",
      kind: explorerContext.kind || "",
      selectedRef: triggerAsset,
      scrollTop: Number(mainScroll?.scrollTop || 0),
      windowScrollY: Number(window.scrollY || 0),
      maximumTreeDepth,
      manualTreeMode,
      treeChildLevels: Object.fromEntries(treeChildLevels),
      expandedTreeNodes: Array.from(treeExpanded)
        .filter(([, expanded]) => expanded)
        .map(([treeNode]) => treeNode),
      triggerKind: trigger.hasAttribute("data-save-view") ? "saved-view"
        : trigger.classList.contains("row-detail") ? "row-detail" : "inspector",
    };
    try {
      sessionStorage.setItem(`${stateStoragePrefix}${token}`, JSON.stringify(state));
      history.replaceState(
        {...(history.state || {}), blockwartExplorerState: token},
        "",
        location.href,
      );
    } catch {
      return "";
    }
    return token;
  }

  const savedViewsSelect = document.querySelector("[data-saved-views]");
  const savedViewsKey = "blockwart-saved-catalog-views:v1:" + explorerContext.principalScope;
  function savedViews() {
    try {
      const entries = JSON.parse(sessionStorage.getItem(savedViewsKey) || "[]");
      return Array.isArray(entries) ? entries.filter(entry => (
        typeof entry.name === "string" && typeof entry.token === "string"
        && readStoredState(entry.token)
      )).slice(0, 20) : [];
    } catch { return []; }
  }
  function renderSavedViews() {
    if (!savedViewsSelect) return;
    while (savedViewsSelect.options.length > 1) savedViewsSelect.remove(1);
    for (const entry of savedViews()) savedViewsSelect.add(new Option(entry.name, entry.token));
  }
  document.querySelector("[data-save-view]")?.addEventListener("click", event => {
    const input = document.querySelector("[data-view-name]");
    if (!input.value.trim()) { input.focus(); return; }
    const status = document.querySelector("[data-view-status]");
    const token = captureExplorerState(event.currentTarget);
    if (!token) { status.textContent = status.dataset.errorCopy; return; }
    try {
      // Each save has its own immutable snapshot, even when names coincide.
      sessionStorage.setItem(savedViewsKey, JSON.stringify([
        ...savedViews().slice(-19), {name: input.value.trim().slice(0, 60), token},
      ]));
      renderSavedViews(); savedViewsSelect.value = token;
      status.textContent = status.dataset.savedCopy;
    } catch { status.textContent = status.dataset.errorCopy; }
  });
  document.querySelector("[data-load-view]")?.addEventListener("click", () => {
    const token = savedViewsSelect.value;
    const state = readStoredState(token);
    if (!state || state.view !== "catalog") return;
    const params = new URLSearchParams({view: "catalog", q: state.query || "", kind: state.kind || "", restore: token});
    location.assign("/?" + params);
  });
  renderSavedViews();

  function restoredStateToken() {
    const url = new URL(location.href);
    return url.searchParams.get("restore")
      || history.state?.blockwartExplorerState
      || "";
  }

  function restoreExplorerState() {
    const token = restoredStateToken();
    const state = readStoredState(token);
    if (
      !state
      || state.version !== 1
      || state.view !== explorerContext.view
      || state.query !== explorerContext.query
      || state.kind !== explorerContext.kind
    ) {
      return false;
    }
    if (savedViewsSelect && Array.from(savedViewsSelect.options).some(option => option.value === token)) {
      savedViewsSelect.value = token;
    }
    if (treeNodes.size) {
      const restoredDepth = Number(state.maximumTreeDepth);
      maximumTreeDepth = Number.isInteger(restoredDepth)
        ? Math.max(0, Math.min(2, restoredDepth))
        : 0;
      const expandedNodes = new Set(
        Array.isArray(state.expandedTreeNodes) ? state.expandedTreeNodes : [],
      );
      for (const treeNode of treeNodes.keys()) {
        treeExpanded.set(treeNode, expandedNodes.has(treeNode));
        const savedLevel = state.treeChildLevels?.[treeNode];
        treeChildLevels.set(treeNode, Number.isInteger(savedLevel) ? Math.max(0, Math.min(2, savedLevel)) : maximumTreeDepth);
      }
      // A restored snapshot carries an explicit branch state; reflecting any
      // deviation from the pure level state as manual mode keeps the level
      // buttons honest instead of claiming a level the tree does not show.
      const pureExpanded = new Set(
        Array.from(treeNodes.entries())
          .filter(([, node]) => Number(node.dataset.treeDepth) < maximumTreeDepth)
          .map(([treeNode]) => treeNode),
      );
      setManualMode(
        state.manualTreeMode === true || expandedNodes.size !== pureExpanded.size
        || Array.from(expandedNodes).some((treeNode) => !pureExpanded.has(treeNode)),
      );
      applyTreeState();
    }
    if (typeof state.selectedRef === "string" && assets[state.selectedRef]) {
      selectAsset(state.selectedRef);
    }
    history.replaceState(
      {...(history.state || {}), blockwartExplorerState: token},
      "",
      (() => {
        const cleanUrl = new URL(location.href);
        cleanUrl.searchParams.delete("restore");
        return `${cleanUrl.pathname}${cleanUrl.search}${cleanUrl.hash}`;
      })(),
    );
    requestAnimationFrame(() => {
      const mainScroll = document.querySelector("[data-main-scroll]");
      if (mainScroll && Number.isFinite(Number(state.scrollTop))) {
        mainScroll.scrollTop = Math.max(0, Number(state.scrollTop));
      }
      if (Number.isFinite(Number(state.windowScrollY))) {
        window.scrollTo({top: Math.max(0, Number(state.windowScrollY))});
      }
      const selectedSelector = state.selectedRef
        ? `[data-asset-ref="${CSS.escape(state.selectedRef)}"]`
        : "";
      const focusTarget = state.triggerKind === "saved-view" ? document.querySelector("[data-saved-views]")
        : state.triggerKind === "row-detail" && selectedSelector
        ? document.querySelector(`${selectedSelector} .row-detail`)
        : document.querySelector("[data-inspector-details]");
      focusTarget?.focus({preventScroll: true});
    });
    return true;
  }

  function focusDetailHeading() {
    requestAnimationFrame(() => {
      document.querySelector("[data-detail-heading]")?.focus({preventScroll: true});
    });
  }

  const isDetailPage = document.documentElement.dataset.page === "detail";
  const restored = !isDetailPage && restoreExplorerState();
  window.addEventListener("pageshow", () => {
    if (isDetailPage) {
      focusDetailHeading();
    } else if (restoredStateToken()) {
      restoreExplorerState();
    }
  });
  if (!restored) {
    const contextSelected = explorerContext.selectedRef
      && assets[explorerContext.selectedRef]
      ? explorerContext.selectedRef
      : "";
    const initiallySelected = selectableNodes.find((node) => (
      !node.hidden && node.classList.contains("selected") && assets[node.dataset.assetRef]
    )) || selectableNodes.find((node) => !node.hidden && assets[node.dataset.assetRef]);
    if (contextSelected) {
      selectAsset(contextSelected);
    } else if (initiallySelected) {
      selectAsset(initiallySelected.dataset.assetRef);
    }
  }

  if (!isDetailPage) {
    for (const trigger of document.querySelectorAll("[data-detail-trigger]")) {
      trigger.addEventListener("click", (event) => {
        if (
          event.defaultPrevented
          || event.button !== 0
          || event.metaKey
          || event.ctrlKey
          || event.shiftKey
          || event.altKey
        ) {
          return;
        }
        const token = captureExplorerState(trigger);
        if (!token) {
          return;
        }
        const target = new URL(trigger.href, location.href);
        if (target.origin !== location.origin) {
          return;
        }
        event.preventDefault();
        target.searchParams.set("return_state", token);
        location.assign(target.href);
      });
    }
  } else {
    focusDetailHeading();
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
  const relationshipLabel = document.querySelector("[data-relationship-label]");
  const relationTargetSelect = document.querySelector("[data-relation-target-select]");
  const relationTypeInput = document.querySelector("[data-relation-type-input]");
  const createRootForm = document.querySelector("[data-create-root-form]");
  const createFields = Array.from(
    (createRootForm || document).querySelectorAll("[data-create-field]"),
  );
  const createGuide = document.querySelector("[data-create-guide]");
  const createParentSummary = document.querySelector("[data-create-parent-summary]");

  function optionChildKinds(option) {
    return (option.dataset.childKinds || "").split(" ").filter(Boolean);
  }

  function updateCreateGuide(guide) {
    if (!createGuide || !guide) {
      return;
    }
    const texts = {
      "[data-create-guide-purpose]": guide.purpose,
      "[data-create-guide-relation]": guide.relation_label,
      "[data-create-guide-placement]": guide.placement,
      "[data-create-guide-later-summary]": guide.deferred_summary,
      "[data-create-guide-later-hint]": guide.deferred_hint,
      "[data-create-guide-panels]": guide.panels,
    };
    for (const [selector, text] of Object.entries(texts)) {
      const target = createGuide.querySelector(selector);
      if (target) {
        target.textContent = text || "";
      }
    }
    const note = createGuide.querySelector("[data-create-guide-note]");
    if (note) {
      note.textContent = guide.parent_note || "";
      note.hidden = !guide.parent_note;
    }
    const deferredList = createGuide.querySelector("[data-create-guide-later-list]");
    if (deferredList) {
      deferredList.replaceChildren(...(guide.deferred_labels || []).map((label) => {
        const item = document.createElement("li");
        item.textContent = label;
        return item;
      }));
    }
  }

  function updateCreateParentSummary(relationType) {
    if (!createParentSummary) {
      return;
    }
    const selected = relationTargetSelect?.selectedOptions[0];
    const template = copy.createParent || {};
    if (!selected || selected.disabled) {
      createParentSummary.textContent = template.none || "";
      return;
    }
    const parent = `${selected.dataset.parentLabel || selected.textContent.trim()} · ${selected.value}`;
    createParentSummary.textContent = (template[relationType] || "{parent}")
      .replace("{parent}", parent);
  }

  function setFieldEnabled(field, enabled) {
    field.hidden = !enabled;
    for (const input of field.querySelectorAll("input, select, textarea")) {
      input.disabled = !enabled;
    }
  }

  function reorderCreateRootFields(schema) {
    const anchor = createRootForm?.querySelector("[data-create-field-order-anchor]");
    const reorderCreateFields = window.BlockwartCreateFieldOrder?.reorderCreateFields;
    if (!anchor || !reorderCreateFields) {
      return;
    }
    const fieldsByKey = new Map(createFields.map((field) => [
      field.getAttribute("data-create-field"),
      field,
    ]));
    reorderCreateFields(createRootForm, anchor, fieldsByKey, schema.create_field_definitions);
  }

  function updateCreateFields() {
    if (!createKindSelect) {
      return;
    }
    const selectedKind = createKindSelect.value;
    const schema = uiSchemas[selectedKind] || {};
    const guide = schema.create_guide || null;
    const relationType = guide?.relation_type || "hosts";
    const attaches = relationType === "attached_to";
    const allowedFields = new Set(schema.create_fields || []);
    const fieldDefinitions = new Map(
      (schema.create_field_definitions || []).map((field) => [field.key, field]),
    );
    reorderCreateRootFields(schema);
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
      // A canonical path shared by several kinds has exactly one control, so
      // its help text has to follow the selected kind instead of staying on
      // whichever kind rendered the page.
      const help = key
        ? field.querySelector(`[data-field-help="${CSS.escape(key)}"]`)
        : null;
      if (label && definition?.label) {
        label.textContent = definition.label;
      }
      if (input && definition) {
        input.placeholder = definition.placeholder || "";
        input.required = Boolean(definition.required);
      }
      if (help && definition) {
        help.textContent = definition.placeholder || "";
      }
    }
    if (platformField) {
      platformField.hidden = !allowedFields.has("platform");
    }
    if (relationshipLabel) {
      relationshipLabel.textContent = attaches
        ? (copy.attachmentParent || relationshipLabel.textContent)
        : (copy.placementParent || relationshipLabel.textContent);
    }
    if (relationTypeInput) {
      relationTypeInput.value = relationType;
    }
    if (relationTargetSelect) {
      for (const option of relationTargetSelect.options) {
        option.disabled = !optionChildKinds(option).includes(selectedKind);
      }
      if (relationTargetSelect.selectedOptions[0]?.disabled) {
        const firstEnabled = Array.from(relationTargetSelect.options).find(
          (option) => !option.disabled,
        );
        if (firstEnabled) {
          relationTargetSelect.value = firstEnabled.value;
        }
      }
    }
    updateCreateGuide(guide);
    updateCreateParentSummary(relationType);
  }

  createKindSelect?.addEventListener("change", updateCreateFields);
  relationTargetSelect?.addEventListener("change", () => {
    const schema = uiSchemas[createKindSelect?.value] || {};
    updateCreateParentSummary(schema.create_guide?.relation_type || "hosts");
  });
  updateCreateFields();
})();
