(() => {
  const cards = Array.from(document.querySelectorAll("[data-object-card]"));
  const createKindSelect = document.querySelector("[data-kind-select]");
  const platformField = document.querySelector("[data-platform-field]");

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

  function updatePlatformField() {
    if (!createKindSelect || !platformField) {
      return;
    }
    platformField.hidden = !["service", "system"].includes(createKindSelect.value);
  }

  createKindSelect?.addEventListener("change", updatePlatformField);
  updatePlatformField();
})();
