// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const source = readFileSync(join(__dirname, '../static/credential-autofill.js'), 'utf8');

function harness({ fixed = false, error = false, valid = true, cell = false } = {}) {
  const frames = [];
  const submissions = [];
  let isAutofilled = false;
  let usernameAutofilled = false;
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
  const username = element(cell ? '' : '0x0sky');
  const prefix = element('0');
  prefix.options = Array.from('0123456789abcdef', value => ({ value, text: '0x' + value }));
  prefix.getAttribute = () => 'Prefix';
  username.matches = (query) => query === ':-webkit-autofill' && usernameAutofilled;
  username.focus = () => {};
  let choices;
  username.closest = () => ({ after(node) { choices = node; } });
  const step = element(cell ? 'identify' : 'sign_in');
  const entry = cell ? {} : null;
  const password = element();
  password.matches = (query) => query === ':-webkit-autofill' && isAutofilled;
  const button = element();
  button.lastChild = { textContent: 'Continue' };
  button.dataset = { loginLabel: 'Sign in' };
  const address = fixed ? element('0x0sky') : null;
  const form = element();
  form.querySelector = (query) => {
    const fields = {
      'input[name="step"]': step,
      '[data-saved-login]': entry,
      'select[name="prefix"]': cell ? prefix : null,
      'input[autocomplete="username"]': username,
      'input[autocomplete="current-password"]': password,
      'button[type="submit"]': button,
      'input[type="hidden"][name="pub_dress"]': address,
    };
    return fields[query] || null;
  };
  form.checkValidity = () => valid;
  form.requestSubmit = (target) => {
    form.dispatch('submit');
    submissions.push(target);
  };
  const document = {
    createElement() {
      return Object.assign(element(), {
        children: [], setAttribute() {}, remove() { choices = null; },
        append(child) { this.children.push(child); },
      });
    },
    querySelector(query) {
      if (query === 'form.identity-form') return form;
      if (query === '.identity-error') return error ? {} : null;
      return null;
    },
  };
  vm.runInNewContext(source, { document, requestAnimationFrame: fn => frames.push(fn) });
  return {
    form, username, password, button, submissions, prefix, step,
    get choices() { return choices; },
    fillAddress(value) {
      username.value = value;
      username.dispatch('input', { inputType: 'insertReplacementText' });
    },
    markUsernameAutofilled(value = true) { usernameAutofilled = value; },
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

test('cell login splits a saved address and submits the matching pair once', () => {
  for (const passwordFirst of [false, true]) {
    const page = harness({ cell: true });
    page.interact();
    if (passwordFirst) {
      page.username.value = 'previous';
      page.autofill('saved password');
      page.flush();
      assert.equal(page.submissions.length, 0);
    }
    page.fillAddress('0x0sky');
    assert.equal(page.prefix.value, '0');
    assert.equal(page.username.value, 'sky');
    if (!passwordFirst) page.autofill('saved password');
    page.flush();
    assert.deepEqual(page.submissions, [page.button]);
    assert.equal(page.step.value, 'sign_in');
    assert.equal(page.username.name, 'pub_dress');
    assert.equal(page.username.value, '0x0sky');
    assert.equal(page.password.value, 'saved password');
  }
});

test('an invalid or missing saved prefix waits for an explicit cell choice', () => {
  for (const saved of ['0xgsky', 'sky']) {
    const page = harness({ cell: true });
    page.interact();
    page.fillAddress(saved);
    page.autofill('saved password');
    page.flush();
    assert.equal(page.username.value, 'sky');
    assert.equal(page.prefix.value, '');
    assert.equal(page.submissions.length, 0);
    assert.deepEqual(page.choices.children.map(choice => choice.textContent),
      Array.from('0123456789abcdef', digit => '0x' + digit));
    page.choices.children[15].dispatch('click');
    page.flush();
    assert.equal(page.username.value, '0xfsky');
    assert.equal(page.password.value, 'saved password');
    assert.deepEqual(page.submissions, [page.button]);
  }
});

test('each clipboard paste parses once, even if it equals the previously displayed body', () => {
  const page = harness({ cell: true });
  page.interact();
  function paste(value) {
    page.username.value = value;
    page.username.dispatch('input', { inputType: 'insertFromPaste' });
    page.username.dispatch('change');
    page.flush();
  }

  paste('0x1da');
  assert.equal(page.prefix.value, '1');
  assert.equal(page.username.value, 'da');
  paste('0x10x0sky');
  assert.equal(page.prefix.value, '1');
  assert.equal(page.username.value, '0x0sky');
  paste('0x0sky');
  assert.equal(page.prefix.value, '0');
  assert.equal(page.username.value, 'sky');
  paste('sky');
  assert.equal(page.prefix.value, '0');
  assert.equal(page.username.value, 'sky');
  assert.equal(page.choices.children.length, 16);
  assert.equal(page.submissions.length, 0);
  page.choices.children[1].dispatch('click');
  page.autofill('saved password');
  page.flush();
  assert.equal(page.username.value, '0x1sky');
  assert.deepEqual(page.submissions, [page.button]);
});

test('a nested split is not parsed again by later autofill signals', () => {
  const page = harness({ cell: true });
  page.interact();
  page.fillAddress('0x10x0sky');
  assert.equal(page.prefix.value, '1');
  assert.equal(page.username.value, '0x0sky');
  page.markUsernameAutofilled();
  page.username.dispatch('change');
  page.autofill('saved password');
  page.flush();
  assert.deepEqual(page.submissions, [page.button]);
  assert.equal(page.username.value, '0x10x0sky');
});

test('a dropped address parses again, even if it equals the previously displayed body', () => {
  const page = harness({ cell: true });
  page.interact();
  page.username.value = '0x10x0sky';
  page.username.dispatch('input', { inputType: 'insertFromPaste' });
  assert.equal(page.username.value, '0x0sky');
  page.username.value = '0x0sky';
  page.username.dispatch('input', { inputType: 'insertFromDrop' });
  assert.equal(page.prefix.value, '0');
  assert.equal(page.username.value, 'sky');
});

test('a pasted bare body replaces the body, keeps the chosen cell and reopens the choices', () => {
  for (const cell of ['0', 'd']) {
    const page = harness({ cell: true });
    page.interact();
    page.username.value = '0x' + cell + 'sky';
    page.username.dispatch('input', { inputType: 'insertFromPaste' });
    assert.equal(page.prefix.value, cell);
    assert.equal(page.username.value, 'sky');
    assert.ok(!page.choices);
    for (const body of ['sky', 'other']) {
      page.username.value = body;
      page.username.dispatch('input', { inputType: 'insertFromPaste' });
      page.flush();
      assert.equal(page.prefix.value, cell);
      assert.equal(page.username.value, body);
      assert.equal(page.choices.children.length, 16);
    }
    page.prefix.dispatch('change');
    assert.ok(!page.choices);
    page.autofill('saved password');
    page.flush();
    assert.equal(page.username.value, '0x' + cell + 'other');
    assert.deepEqual(page.submissions, [page.button]);
  }
});

test('typed bodies stay manual and a later bare paste keeps the chosen cell', () => {
  const page = harness({ cell: true });
  page.interact();
  page.prefix.value = 'd';
  page.username.value = 'sky';
  page.username.dispatch('input', { inputType: 'insertText' });
  assert.ok(!page.choices);
  page.username.value = 'sky';
  page.username.dispatch('input', { inputType: 'insertFromPaste' });
  assert.equal(page.prefix.value, 'd');
  assert.equal(page.username.value, 'sky');
  assert.equal(page.choices.children.length, 16);
  page.username.value = '0x1new';
  page.username.dispatch('input', { inputType: 'insertFromPaste' });
  assert.equal(page.prefix.value, '1');
  assert.equal(page.username.value, 'new');
  assert.ok(!page.choices);
});
