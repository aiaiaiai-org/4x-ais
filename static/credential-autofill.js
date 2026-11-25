// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

// The browser's password manager owns credentials. This script does not store,
// inspect, send, or log a password; it only requests the existing form submit
// after an explicitly initiated password AutoFill. Manual typing stays manual.
(() => {
  'use strict';

  const form = document.querySelector('form.identity-form');
  if (!form || form.querySelector('input[name="step"]')?.value !== 'sign_in') return;

  const username = form.querySelector('input[autocomplete="username"]');
  const password = form.querySelector('input[autocomplete="current-password"]');
  const button = form.querySelector('button[type="submit"]');
  const fixedAddress = form.querySelector('input[type="hidden"][name="pub_dress"]');
  if (!username || !password || !button) return;

  let interacted = false;
  let passwordAutofilled = false;
  let submitting = false;
  let scheduled = false;

  function hasBrowserAutofill() {
    try {
      return password.matches(':-webkit-autofill');
    } catch {
      return false;
    }
  }

  function maybeSubmit() {
    if (!interacted || !passwordAutofilled || submitting || scheduled) return;
    scheduled = true;
    // Password managers may fill the username and password in separate events.
    requestAnimationFrame(() => {
      scheduled = false;
      if (submitting || !interacted || !passwordAutofilled) return;
      // An invalid-credentials response must never trigger an autofill retry loop.
      if (document.querySelector('.identity-error')) return;
      if (!username.value.trim() || !password.value || !form.checkValidity()) return;
      // The slug skin intentionally hides the full address. Never silently
      // switch its account when a different credential was selected.
      if (fixedAddress && username.value !== fixedAddress.value) return;
      submitting = true;
      form.requestSubmit(button); // validates and sends the existing OIDC form
    });
  }

  form.addEventListener('pointerdown', () => { interacted = true; }, { passive: true });
  form.addEventListener('touchstart', () => { interacted = true; }, { passive: true });
  form.addEventListener('keydown', () => { interacted = true; });
  form.addEventListener('submit', () => { submitting = true; });

  password.addEventListener('animationstart', (event) => {
    if (event.animationName !== 'credential-autofill-start' || !interacted) return;
    passwordAutofilled = true;
    maybeSubmit();
  });
  password.addEventListener('input', (event) => {
    if (!interacted || !event.isTrusted) return;
    // Safari uses :-webkit-autofill; some managers emit a replacement input.
    if (hasBrowserAutofill() ||
        event.inputType === 'insertReplacementText' ||
        event.inputType === 'insertFromAutoFill') {
      passwordAutofilled = true;
      maybeSubmit();
    }
  });
  password.addEventListener('change', () => {
    if (interacted && hasBrowserAutofill()) {
      passwordAutofilled = true;
      maybeSubmit();
    }
  });
  username.addEventListener('input', maybeSubmit);
  username.addEventListener('change', maybeSubmit);
})();
