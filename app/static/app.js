(() => {
  const dialog = document.querySelector("#confirm-dialog");
  const title = dialog?.querySelector("#confirm-dialog-title");
  const message = dialog?.querySelector("#confirm-dialog-message");
  const confirmButton = dialog?.querySelector("[data-dialog-confirm]");
  const cancelButton = dialog?.querySelector("[data-dialog-cancel]");
  const dialogSupported = Boolean(dialog && typeof dialog.showModal === "function");
  let pendingForm = null;
  let bypassForm = null;
  let previousFocus = null;

  if (dialogSupported) {
    document.querySelectorAll("[data-confirm-trigger]").forEach((button) => {
      button.disabled = false;
    });
  }

  const setBusy = (form) => {
    if (form.dataset.submitting === "true") return false;
    form.dataset.submitting = "true";
    form.setAttribute("aria-busy", "true");
    const submitter = form.querySelector('button[type="submit"], input[type="submit"]');
    if (submitter) {
      const loadingLabel = submitter.dataset.loadingLabel;
      if (loadingLabel && submitter.tagName === "BUTTON") {
        submitter.dataset.originalLabel = submitter.textContent.trim();
        submitter.textContent = loadingLabel;
      }
      submitter.disabled = true;
    }
    return true;
  };

  const openConfirmation = (form) => {
    if (!dialogSupported) return false;
    pendingForm = form;
    previousFocus = document.activeElement;
    if (title) title.textContent = form.dataset.confirmTitle || "Are you sure?";
    if (message) message.textContent = form.dataset.confirmMessage || "Please confirm this action.";
    if (confirmButton) confirmButton.textContent = form.dataset.confirmLabel || "Continue";
    dialog.showModal();
    (cancelButton || confirmButton)?.focus();
    return true;
  };

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.hasAttribute("data-confirm-dialog") && bypassForm !== form) {
      if (openConfirmation(form)) {
        event.preventDefault();
        return;
      }
    }
    if (bypassForm === form) bypassForm = null;
    if (form.dataset.submitOnce === "true" && !setBusy(form)) {
      event.preventDefault();
    }
  });

  cancelButton?.addEventListener("click", () => {
    pendingForm = null;
    dialog.close();
    previousFocus?.focus?.();
    previousFocus = null;
  });

  confirmButton?.addEventListener("click", () => {
    const form = pendingForm;
    pendingForm = null;
    dialog.close();
    if (!form) return;
    bypassForm = form;
    form.requestSubmit();
    if (bypassForm === form) bypassForm = null;
    previousFocus = null;
  });

  dialog?.addEventListener("cancel", () => {
    pendingForm = null;
    const focusTarget = previousFocus;
    previousFocus = null;
    window.requestAnimationFrame(() => focusTarget?.focus?.());
  });

  window.addEventListener("pageshow", () => {
    document.querySelectorAll('[data-submit-once="true"]').forEach((form) => {
      const wasSubmitting = form.dataset.submitting === "true";
      form.dataset.submitting = "false";
      form.removeAttribute("aria-busy");
      const submitter = form.querySelector('button[type="submit"], input[type="submit"]');
      if (!submitter) return;
      if (wasSubmitting || (dialogSupported && submitter.hasAttribute("data-confirm-trigger"))) {
        submitter.disabled = false;
      }
      if (wasSubmitting && submitter.dataset.originalLabel && submitter.tagName === "BUTTON") {
        submitter.textContent = submitter.dataset.originalLabel;
      }
    });
  });

  const invalidField = document.querySelector('[aria-invalid="true"]');
  if (invalidField instanceof HTMLElement) {
    window.requestAnimationFrame(() => invalidField.focus());
  }
})();
