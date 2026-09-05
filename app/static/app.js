(() => {
  const themeStorageKey = "earn-proxy-theme";
  const savedTheme = window.localStorage?.getItem(themeStorageKey);
  if (savedTheme === "dark") document.body.classList.add("theme-dark");

  const sidebar = document.querySelector("#app-sidebar");
  const menuToggle = document.querySelector("#mobile-menu-toggle");
  const sidebarOverlay = document.querySelector("#sidebar-overlay");
  const mobileQuery = window.matchMedia("(max-width: 1099px)");
  const focusableSelector =
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  let drawerOpen = false;

  const syncSidebarMode = () => {
    if (!sidebar) return;
    const mobile = mobileQuery.matches;
    if (!mobile) {
      drawerOpen = false;
      sidebar.hidden = false;
      sidebar.inert = false;
      sidebar.setAttribute("aria-hidden", "false");
      sidebar.classList.remove("open");
      sidebarOverlay?.classList.remove("open");
      if (sidebarOverlay) sidebarOverlay.hidden = true;
      menuToggle?.setAttribute("aria-expanded", "false");
      document.body.classList.remove("drawer-open");
      return;
    }
    if (!drawerOpen) {
      sidebar.classList.remove("open");
      sidebar.hidden = true;
      sidebar.inert = true;
      sidebar.setAttribute("aria-hidden", "true");
      sidebarOverlay?.classList.remove("open");
      if (sidebarOverlay) sidebarOverlay.hidden = true;
      menuToggle?.setAttribute("aria-expanded", "false");
      document.body.classList.remove("drawer-open");
    }
  };

  const closeSidebar = ({ restoreFocus = true } = {}) => {
    if (!sidebar || !mobileQuery.matches) return;
    drawerOpen = false;
    sidebar.classList.remove("open");
    sidebar.inert = true;
    sidebar.setAttribute("aria-hidden", "true");
    sidebar.hidden = true;
    sidebarOverlay?.classList.remove("open");
    if (sidebarOverlay) sidebarOverlay.hidden = true;
    menuToggle?.setAttribute("aria-expanded", "false");
    document.body.classList.remove("drawer-open");
    if (restoreFocus) window.requestAnimationFrame(() => menuToggle?.focus());
  };

  const openSidebar = () => {
    if (!sidebar || !mobileQuery.matches) return;
    drawerOpen = true;
    sidebar.hidden = false;
    sidebar.inert = false;
    sidebar.setAttribute("aria-hidden", "false");
    sidebar.classList.add("open");
    if (sidebarOverlay) sidebarOverlay.hidden = false;
    sidebarOverlay?.classList.add("open");
    menuToggle?.setAttribute("aria-expanded", "true");
    document.body.classList.add("drawer-open");
    window.requestAnimationFrame(() => {
      const focusTarget = sidebar.querySelector('[aria-current="page"]') || sidebar.querySelector(".nav-item, button");
      focusTarget?.focus();
    });
  };

  syncSidebarMode();
  menuToggle?.addEventListener("click", () => (drawerOpen ? closeSidebar() : openSidebar()));
  sidebarOverlay?.addEventListener("click", () => closeSidebar());
  sidebar?.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => closeSidebar({ restoreFocus: false })));
  mobileQuery.addEventListener?.("change", syncSidebarMode);

  const legacyDashboardRoutes = {
    "#add-proxy": "/dashboard/proxies",
    "#proxy-status": "/dashboard/proxies",
    "#overview": "/dashboard/earnings",
    "#wallet": "/dashboard/wallet",
    "#request-payout": "/dashboard/wallet",
    "#payout-history": "/dashboard/wallet",
  };
  const legacyRoute = legacyDashboardRoutes[window.location.hash];
  if (window.location.pathname === "/dashboard" && legacyRoute) {
    window.location.replace(`${legacyRoute}${window.location.hash}`);
  }

  const themeToggle = document.querySelector("[data-theme-toggle]");
  themeToggle?.setAttribute("aria-pressed", String(document.body.classList.contains("theme-dark")));
  themeToggle?.addEventListener("click", () => {
    const dark = document.body.classList.toggle("theme-dark");
    window.localStorage?.setItem(themeStorageKey, dark ? "dark" : "light");
    themeToggle.setAttribute("aria-pressed", String(dark));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && drawerOpen) closeSidebar();
    if (event.key === "Tab" && drawerOpen && sidebar) {
      const focusableElements = [...sidebar.querySelectorAll(focusableSelector)];
      if (!focusableElements.length) return;
      const first = focusableElements[0];
      const last = focusableElements[focusableElements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
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
