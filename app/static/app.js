(() => {
  const sidebar = document.querySelector("#app-sidebar");
  const menuToggle = document.querySelector("#mobile-menu-toggle");
  const sidebarOverlay = document.querySelector("#sidebar-overlay");

  const closeSidebar = () => {
    sidebar?.classList.remove("open");
    sidebarOverlay?.classList.remove("open");
    menuToggle?.setAttribute("aria-expanded", "false");
  };

  menuToggle?.addEventListener("click", () => {
    const open = !sidebar?.classList.contains("open");
    sidebar?.classList.toggle("open", open);
    sidebarOverlay?.classList.toggle("open", open);
    menuToggle.setAttribute("aria-expanded", String(open));
    if (open) sidebar?.querySelector('[aria-current="page"]')?.focus();
  });
  sidebarOverlay?.addEventListener("click", closeSidebar);
  sidebar?.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", closeSidebar));

  const themeToggle = document.querySelector("[data-theme-toggle]");
  themeToggle?.addEventListener("click", () => {
    document.body.classList.toggle("theme-dark");
    themeToggle.setAttribute("aria-pressed", String(document.body.classList.contains("theme-dark")));
  });

  const pageSearch = document.querySelector("[data-page-search]");
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      pageSearch?.focus();
    }
    if (event.key === "Escape") closeSidebar();
  });

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

  const copyStatus = document.querySelector("#copy-status");
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) return;
      const value = target.textContent.trim();
      try {
        await navigator.clipboard.writeText(value);
        if (copyStatus) copyStatus.textContent = "Copied to clipboard.";
      } catch (_error) {
        if (copyStatus) copyStatus.textContent = "Copy is unavailable here; select the text manually.";
      }
    });
  });

  const invalidField = document.querySelector('[aria-invalid="true"]');
  if (invalidField instanceof HTMLElement) {
    window.requestAnimationFrame(() => invalidField.focus());
  }

  const payoutAmount = document.querySelector("#amount_usd");
  const payoutFee = document.querySelector("[data-payout-fee]");
  const payoutNet = document.querySelector("[data-payout-net]");
  if (payoutAmount && payoutFee && payoutNet) {
    const formatUsd = (value) => `$${value.toFixed(6)}`;
    const updatePayoutQuote = () => {
      const amount = Number.parseFloat(payoutAmount.value || "0");
      if (!Number.isFinite(amount) || amount <= 0) {
        payoutFee.textContent = "$0.000000";
        payoutNet.textContent = "$0.000000";
        return;
      }
      const rate = amount >= 50 ? 0.02 : 0.10;
      const fee = amount * rate;
      payoutFee.textContent = formatUsd(fee);
      payoutNet.textContent = formatUsd(Math.max(0, amount - fee));
    };
    payoutAmount.addEventListener("input", updatePayoutQuote);
    updatePayoutQuote();
  }
})();
