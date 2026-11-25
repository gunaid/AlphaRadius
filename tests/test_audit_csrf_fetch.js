'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../web/templates/base.html'), 'utf8');
const code = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
const calls = [];
const window = {
    location: {href: 'https://fixture.invalid/dashboard', origin: 'https://fixture.invalid'},
    fetch: (input, options) => calls.push({input, options})
};
// Minimal form element: base.html also attaches the token to native submits.
class HTMLFormElement {
    constructor(attributes) { this.attributes = attributes; this.children = []; this.submitted = 0; }
    getAttribute(name) { return this.attributes[name] ?? null; }
    querySelector() { return this.children.find(child => child.name === 'csrf_token') || null; }
    appendChild(child) { this.children.push(child); }
    submit() { this.submitted++; }
}
const listeners = [];
vm.runInNewContext(code, {window, URL, Request, Headers, HTMLFormElement,
    document: {querySelector: () => ({content: 'fixture-csrf'}), createElement: () => ({}),
               addEventListener: (type, handler) => listeners.push({type, handler})}});
for (const route of ['/api/tools/nas-diagnostics/test-coa-port',
    '/api/tools/nas-diagnostics/send-coa-disconnect',
    '/api/automation-rules/toggle', '/api/automation-rules/run',
    '/api/backups/create', '/api/system-services/action', '/api/whatsapp/settings/save']) {
    window.fetch(route, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});
    const options = calls.at(-1).options;
    assert.equal(options.headers.get('X-CSRF-Token'), 'fixture-csrf');
    assert.equal(options.headers.get('Content-Type'), 'application/json');
    assert.equal(options.body, '{}');
}
window.fetch('https://external.invalid/api/automation-rules/run', {method: 'POST'});
assert.equal(calls.at(-1).options.headers, undefined);
window.fetch('/api/automation-rules/run', {method: 'GET'});
assert.equal(calls.at(-1).options.headers, undefined);
for (const method of ['PUT', 'PATCH', 'DELETE']) {
    window.fetch('/api/future-admin-route', {method});
    assert.equal(calls.at(-1).options.headers.get('X-CSRF-Token'), 'fixture-csrf');
}
const form = new HTMLFormElement({method: 'post', action: '/vouchers/generate'});
form.submit();
assert.equal(form.submitted, 1);
assert.equal(form.children[0].value, 'fixture-csrf');
const external = new HTMLFormElement({method: 'post', action: 'https://external.invalid/x'});
external.submit();
assert.equal(external.children.length, 0);
assert.equal(listeners.filter(l => l.type === 'submit').length, 1);
console.log('PASS: administrative writes retain payloads; no token on GET or external origin');
