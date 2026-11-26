// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

// The browser's password manager owns credentials. This script does not store,
// inspect, send, or log a password; it only requests the existing form submit
// after an explicitly initiated password AutoFill. Manual typing stays manual.
(() => {
  'use strict';

  const form = document.querySelector('form.identity-form');
  const step = form?.querySelector('input[name="step"]');
  const entry = form?.querySelector('[data-saved-login]');
  if (!entry && step?.value !== 'sign_in') return;

  const username = form.querySelector('input[autocomplete="username"]');
  const password = form.querySelector('input[autocomplete="current-password"]');
  const button = form.querySelector('button[type="submit"]');
  const fixedAddress = form.querySelector('input[type="hidden"][name="pub_dress"]');
  if (!username || !password || !button) return;

  let interacted = false;
  let passwordAutofilled = false;
  let submitting = false;
  let scheduled = false;

  const prefix = form.querySelector('select[name="prefix"]');
  let lastBody;
  let choices;
  let addressConfirmed = !entry;
  let continueLabel;
  if (entry) {
    username.name = 'pub_dress';
    entry.hidden = false;
    entry.disabled = false;
    continueLabel = button.lastChild.textContent;
  }

  function updateButton() {
    if (entry) button.lastChild.textContent = password.value ? button.dataset.loginLabel : continueLabel;
  }

  function closeChoices() {
    choices?.remove();
    choices = null;
  }

  function openChoices() {
    prefix.value = '';
    if (choices) return;
    choices = document.createElement('div');
    choices.className = 'prefix-choices';
    choices.setAttribute('role', 'group');
    choices.setAttribute('aria-label', prefix.getAttribute('aria-label'));
    for (const option of prefix.options) {
      const choice = document.createElement('button');
      choice.type = 'button';
      choice.textContent = option.text;
      choice.addEventListener('click', () => {
        prefix.value = option.value;
        closeChoices();
        username.focus();
        maybeSubmit();
      });
      choices.append(choice);
    }
    username.closest('.address-field').after(choices);
  }

  function splitAddress(saved = false) {
    if (!prefix || lastBody === username.value) return;
    const match = /^0x(.?)(.*)$/isu.exec(username.value);
    if (!match && !saved) return;
    addressConfirmed = true;
    const digit = match?.[1].toLowerCase();
    if (match) username.value = match[2];
    lastBody = username.value;
    if (digit && /^[0-9a-f]$/.test(digit)) {
      prefix.value = digit;
      closeChoices();
    } else {
      openChoices();
    }
  }

  if (prefix) {
    prefix.required = true;
    const wrapper = form.querySelector('[data-sign-in-prefix]');
    if (wrapper) {
      splitAddress();
      wrapper.hidden = false;
    }
    prefix.addEventListener('change', () => {
      closeChoices();
      maybeSubmit();
    });
    username.addEventListener('input', (event) => {
      // Typing edits the body. A paste or manager may replace it with a full address.
      if (event.inputType === 'insertText' || event.inputType?.startsWith('delete')) {
        addressConfirmed = true;
        lastBody = undefined;
        return;
      }
      splitAddress(event.inputType === 'insertFromPaste' || event.inputType === 'insertReplacementText' ||
        event.inputType === 'insertFromAutoFill' || username.matches(':-webkit-autofill'));
    });
    username.addEventListener('change', () => {
      if (username.matches(':-webkit-autofill')) splitAddress(true);
    });
    form.addEventListener('submit', () => {
      if (!password.value) {
        if (entry) username.name = 'slug';
        return;
      }
      step.value = 'sign_in';
      username.name = 'pub_dress';
      username.value = '0x' + prefix.value + username.value;
    });
  }

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
      if (prefix && username.matches(':-webkit-autofill')) splitAddress(true);
      if (!addressConfirmed || (prefix && !prefix.value)) return;
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
    updateButton();
    if (event.animationName !== 'credential-autofill-start' || !interacted) return;
    passwordAutofilled = true;
    maybeSubmit();
  });
  password.addEventListener('input', (event) => {
    updateButton();
    if (event.inputType === 'insertText' || event.inputType?.startsWith('delete')) {
      passwordAutofilled = false;
      return;
    }
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
    updateButton();
    if (interacted && hasBrowserAutofill()) {
      passwordAutofilled = true;
      maybeSubmit();
    }
  });
  username.addEventListener('input', maybeSubmit);
  username.addEventListener('change', maybeSubmit);
})();
