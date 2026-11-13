(() => {
  const dialog = document.querySelector('[data-smart-dialog]');
  const form = dialog?.querySelector('[data-smart-form]');
  let controller;
  let timer;
  let opener;
  let requestId = 0;
  let hasOpened = false;
  const results = dialog?.querySelector('[data-smart-results]');
  async function search() {
    const currentRequest = ++requestId;
    controller?.abort();
    controller = new AbortController();
    const params = new URLSearchParams(new FormData(form));
    params.set('fragment', 'true');
    try {
      const response = await fetch('/search?' + params, {signal: controller.signal});
      if (!response.ok) throw new Error('Search unavailable');
      const html = await response.text();
      if (currentRequest === requestId && dialog.open) results.innerHTML = html;
    } catch (error) {
      if (error.name !== 'AbortError') results.textContent = document.documentElement.lang === 'de' ? 'Suche nicht verfügbar. Bitte erneut versuchen.' : 'Search unavailable. Please try again.';
    }
  }
  function open(event) {
    event?.preventDefault();
    opener = event?.currentTarget instanceof HTMLElement ? event.currentTarget : document.activeElement;
    if (!hasOpened) {
      form.reset(); // First global entry is All Types, never the catalog type.
      results.replaceChildren();
      hasOpened = true;
    }
    if (!dialog.open) dialog.showModal();
    form.elements.q.focus();
    if (form.elements.q.value) search();
  }
  document.querySelectorAll('[data-smart-open]').forEach(link => link.addEventListener('click', open));
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && dialog) open(event);
  });
  dialog?.querySelector('[data-smart-close]').addEventListener('click', () => dialog.close());
  dialog?.addEventListener('close', () => { controller?.abort(); clearTimeout(timer); opener?.focus(); });
  form?.addEventListener('input', () => {
    requestId++; controller?.abort(); results.replaceChildren();
    clearTimeout(timer); timer = setTimeout(search, 180);
  });
  form?.addEventListener('change', () => { clearTimeout(timer); search(); });
  form?.addEventListener('submit', event => { event.preventDefault(); clearTimeout(timer); search(); });
  form?.elements.q.addEventListener('keydown', event => {
    if (event.key === 'Enter' && results.querySelector('[data-search-hit]')) {
      event.preventDefault(); results.querySelector('[data-search-hit]').click();
    }
  });
  results?.addEventListener('click', event => {
    if (event.target.closest('[data-smart-expand]')) {
      event.preventDefault(); form.elements.object_kind.value = ''; search();
    }
  });
  if (document.querySelector('[data-update-badge]')) {
    fetch('/navigation/updates').then(response => response.ok ? response.json() : null).then(data => {
      if (!Number.isInteger(data?.count) || data.count <= 0) return;
      document.querySelectorAll('[data-update-badge]').forEach(badge => { badge.textContent = data.count; badge.hidden = false; });
    }).catch(() => {});
  }
})();
