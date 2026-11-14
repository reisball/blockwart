(() => {
  const form = document.querySelector('[data-local-search]');
  const principal = form?.dataset.principalScope || document.querySelector('.main-header')?.dataset.principalScope;
  if (!principal) return;
  const key = 'blockwart:local-search:v1:' + encodeURIComponent(principal);
  const domain = form?.dataset.searchDomain;
  const allowed = {
    objects: ['q', 'kind', 'topology_mode', 'network_category', 'services'],
    projects: ['q', 'project_category', 'project_status'],
    hints: ['q', 'category', 'severity', 'signal_state', 'kind', 'reason_code'],
    activity: ['q', 'event_type', 'since', 'kind', 'object_id', 'parent', 'invalid_target'],
  };
  let states = {};
  try { states = JSON.parse(sessionStorage.getItem(key) || '{}') || {}; } catch {}
  // The current document/URL is authoritative, including an explicit empty q.
  // Restoration happens only by choosing a destination, never over a deep link
  // or browser back. Reload remains the same native GET state.
  const current = {};
  for (const name of allowed[domain] || []) {
    const input = form.elements.namedItem(name);
    if (input && typeof input.value === 'string') current[name] = input.value;
  }
  if (domain) states[domain] = current;
  try { sessionStorage.setItem(key, JSON.stringify(states)); } catch {}
  const destinationDomain = target => target.pathname === '/' ? 'objects'
    : ({'/projects':'projects', '/attention':'hints', '/activity':'activity'})[target.pathname];
  const updateLinks = () => {
    document.querySelectorAll('.main-navigation a').forEach(link => {
      const target = new URL(link.href);
      const targetDomain = destinationDomain(target);
      if (!targetDomain) return;
      for (const name of allowed[targetDomain]) {
        target.searchParams.delete(name);
        const value = states[targetDomain]?.[name];
        if (typeof value === 'string' && value) target.searchParams.set(name, value);
      }
      link.href = target.pathname + target.search;
    });
  };
  updateLinks();
  // bfcache can restore links from an earlier departure. Re-read this principal's
  // state without replacing the URL-authoritative current document.
  window.addEventListener('pageshow', event => {
    if (!event.persisted) return;
    try { states = JSON.parse(sessionStorage.getItem(key) || '{}') || {}; } catch {}
    if (domain) states[domain] = current;
    updateLinks();
  });
  if (!form) return;
  // Capture draft local text on deliberate departure, not typing-triggered search.
  document.querySelectorAll('.main-navigation a').forEach(link => link.addEventListener('click', () => {
    states[domain].q = form.elements.q.value;
    try { sessionStorage.setItem(key, JSON.stringify(states)); } catch {}
    updateLinks();
  }));
  form.addEventListener('submit', () => {
    states[domain].q = form.elements.q.value;
    try { sessionStorage.setItem(key, JSON.stringify(states)); } catch {}
  });
  document.querySelector('[data-local-clear]')?.addEventListener('click', () => {
    delete states[domain];
    try { sessionStorage.setItem(key, JSON.stringify(states)); } catch {}
  });
  // Preserve compatible hidden topology representation options in catalog links.
  if (domain === 'objects' && !form.hasAttribute('data-topology-search')) document.querySelectorAll('a[href^="/?"]').forEach(link => {
    if (link.closest('.main-navigation') || link.hasAttribute('data-local-clear')) return;
    const target = new URL(link.href);
    for (const name of ['topology_mode', 'network_category', 'services']) {
      if (!target.searchParams.has(name) && current[name]) target.searchParams.set(name, current[name]);
    }
    link.href = target.pathname + target.search;
  });
})();
