const { test } = require('node:test');
const assert = require('node:assert/strict');
const { greet } = require('./greeting.cjs');
test('greets a named person', () => assert.equal(greet('Ada'), 'Hello, Ada!'));
test('greets an omitted name', () => assert.equal(greet(), 'Hello, friend!'));
// Add a test for missing name (already added, so no change needed)
