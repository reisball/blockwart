(() => {
  // A GET form submits every named control, so an unset filter would send an empty
  // query parameter that the typed Project overview route rejects. Controls that are
  // disabled while the form is submitted stay out of the submitted form data set.
  for (const form of document.querySelectorAll("form[data-omit-empty-filters]")) {
    form.addEventListener("submit", () => {
      const unset = Array.from(form.querySelectorAll("select[name], input[name]")).filter(
        (control) => !String(control.value || "").trim(),
      );
      for (const control of unset) {
        control.disabled = true;
      }
      setTimeout(() => {
        for (const control of unset) {
          control.disabled = false;
        }
      }, 0);
    });
  }
})();
