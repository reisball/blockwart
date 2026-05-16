(() => {
  const cards = Array.from(document.querySelectorAll("[data-object-card]"));

  function closeCard(card) {
    card.classList.remove("is-expanded");
    card.querySelector("[data-object-toggle]")?.setAttribute("aria-expanded", "false");
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

  for (const card of cards) {
    const toggle = card.querySelector("[data-object-toggle]");
    for (const detailLink of card.querySelectorAll("[data-detail-link]")) {
      detailLink.addEventListener("click", (event) => event.stopPropagation());
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
      return;
    }
    closeAll();
  });
})();
