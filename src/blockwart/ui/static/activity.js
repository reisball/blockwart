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
