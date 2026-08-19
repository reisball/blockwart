(() => {
  function createFieldOrder(fieldDefinitions, renderedFieldKeys) {
    const rendered = new Set(renderedFieldKeys);
    const ordered = [];
    const seen = new Set();
    for (const definition of fieldDefinitions || []) {
      const key = definition?.key;
      if (typeof key === "string" && rendered.has(key) && !seen.has(key)) {
        ordered.push(key);
        seen.add(key);
      }
    }
    for (const key of renderedFieldKeys) {
      if (!seen.has(key)) {
        ordered.push(key);
        seen.add(key);
      }
    }
    return ordered;
  }

  function reorderCreateFields(container, anchor, fieldsByKey, fieldDefinitions) {
    const order = createFieldOrder(fieldDefinitions, Array.from(fieldsByKey.keys()));
    for (const key of order) {
      container.insertBefore(fieldsByKey.get(key), anchor);
    }
    return order;
  }

  const api = { createFieldOrder, reorderCreateFields };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  (typeof window === "undefined" ? globalThis : window).BlockwartCreateFieldOrder = api;
})();
