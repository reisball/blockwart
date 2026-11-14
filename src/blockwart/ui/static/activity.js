// A target must be an exact authorized reference, not arbitrary free text.
// The server independently validates it and retains the previous target on error.
(() => {
  const target = document.querySelector('[data-activity-target]');
  const options = new Set(Array.from(document.querySelectorAll('#activity-targets option')).map(option => option.value));
  target?.form.addEventListener('submit', event => {
    const invalid = target.value && !options.has(target.value);
    if (invalid) {
      event.preventDefault();
      target.setCustomValidity(document.documentElement.lang === 'de' ? 'Bitte ein eindeutiges Ziel aus der Liste wählen.' : 'Choose an unambiguous target from the list.');
      target.reportValidity();
    }
  });
  target?.addEventListener('input', () => target.setCustomValidity(''));
})();

// Progressive enhancement only: retain exact RFC3339 until the user changes date.
(() => {
  const raw = document.querySelector('[data-activity-since]');
  if (!raw) return;
  const date = document.createElement('input');
  date.type = 'date';
  if (date.type !== 'date') return;
  date.dataset.activityDate = '';
  const parsed = raw.value ? new Date(raw.value) : null;
  if (parsed && Number.isNaN(parsed.getTime())) return;
  date.value = parsed ? parsed.toISOString().slice(0, 10) : '';
  date.title = raw.value;
  const label = document.createElement('label');
  label.append(document.createTextNode(raw.dataset.dateLabel), date);
  raw.parentElement.before(label);
  raw.parentElement.hidden = true;
  date.addEventListener('change', () => {
    raw.value = date.value ? date.value + 'T00:00:00Z' : '';
    date.title = raw.value;
  });
})();
