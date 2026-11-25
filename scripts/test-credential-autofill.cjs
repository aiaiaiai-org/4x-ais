// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const source = readFileSync(join(__dirname, '../static/credential-autofill.js'), 'utf8');

function harness({ fixed = false, error = false, valid = true } = {}) {
  const frames = [];
  const submissions = [];
  let isAutofilled = false;
  const element = (value = '') => {
    const listeners = {};
    return {
      value,
      addEventListener(name, fn) {
        (listeners[name] ||= []).push(fn);
      },
      dispatch(name, data = {}) {
        for (const fn of listeners[name] || []) fn({ target: this, ...data });
      },
    };
  };
  const username = element('0x0sky');
  const password = element();
  password.matches = (query) => query === ':-webkit-autofill' && isAutofilled;
  const button = element();
  const address = fixed ? element('0x0sky') : null;
  const form = element();
  form.querySelector = (query) => {
    const fields = {
      'input[name="step"]': element('sign_in'),
      'input[autocomplete="username"]': username,
      'input[autocomplete="current-password"]': password,
      'button[type="submit"]': button,
      'input[type="hidden"][name="pub_dress"]': address,
    };
    return fields[query] || null;
  };
  form.checkValidity = () => valid;
  form.requestSubmit = (target) => submissions.push(target);
  const document = {
    querySelector(query) {
      if (query === 'form.identity-form') return form;
      if (query === '.identity-error') return error ? {} : null;
      return null;
    },
  };
  vm.runInNewContext(source, { document, requestAnimationFrame: fn => frames.push(fn) });
  return {
    form, username, password, button, submissions,
    interact() { form.dispatch('pointerdown'); },
    type(value) {
      password.value = value;
      password.dispatch('input', { isTrusted: true, inputType: 'insertText' });
    },
    autofill(value) {
      password.value = value;
      isAutofilled = true;
      password.dispatch('input', { isTrusted: true, inputType: 'insertReplacementText' });
    },
    animateAutofill() {
      password.dispatch('animationstart', { animationName: 'credential-autofill-start' });
    },
    flush() { while (frames.length) frames.shift()(); },
  };
}

test('manual typing never automatically submits', () => {
  const page = harness();
  page.interact();
  page.type('manual password');
  page.flush();
  assert.equal(page.submissions.length, 0);
});

test('automatic initial fill without a user action never submits', () => {
  const page = harness();
  page.autofill('saved password');
  page.flush();
  assert.equal(page.submissions.length, 0);
});

test('selected password-manager credentials submit once', () => {
  const page = harness();
  page.interact();
  page.autofill('saved password');
  page.flush();
  page.animateAutofill();
  page.flush();
  assert.deepEqual(page.submissions, [page.button]);
});

test('username and password can arrive in separate autofill events', () => {
  const page = harness();
  page.username.value = '';
  page.interact();
  page.autofill('saved password');
  page.flush();
  assert.equal(page.submissions.length, 0);
  page.username.value = '0x0sky';
  page.username.dispatch('change');
  page.flush();
  assert.equal(page.submissions.length, 1);
});

test('slug skin cannot silently switch a hidden address', () => {
  const page = harness({ fixed: true });
  page.username.value = '0x1another';
  page.interact();
  page.autofill('saved password');
  page.flush();
  assert.equal(page.submissions.length, 0);
});

test('credential errors and invalid forms never trigger retry loops', () => {
  for (const config of [{ error: true }, { valid: false }]) {
    const page = harness(config);
    page.interact();
    page.autofill('saved password');
    page.flush();
    assert.equal(page.submissions.length, 0);
  }
});

test('autofill animation can trigger submission without an input event', () => {
  const page = harness();
  page.interact();
  page.password.value = 'saved password';
  page.animateAutofill();
  page.flush();
  assert.equal(page.submissions.length, 1);
});
