import assert from "node:assert/strict";
import { test } from "node:test";
import { checkableUrl, domainOf, normaliseServer, validToken } from "../dist/core.js";

test("only web pages are checkable", () => {
  assert.equal(checkableUrl("chrome://settings"), null);
  assert.equal(checkableUrl("file:///etc/passwd"), null);
  assert.equal(checkableUrl("http://localhost:3000/"), null);
  assert.equal(checkableUrl("https://example.com/a?b=1"), "https://example.com/a?b=1");
});

test("warnings send only the domain", () => {
  assert.equal(domainOf("https://Login.Example.com/reset?token=secret#x"), "login.example.com");
});

test("settings helpers", () => {
  assert.equal(normaliseServer("scam.example.com/"), "https://scam.example.com");
  assert.ok(validToken("pse_" + "a".repeat(40)));
  assert.ok(!validToken("psk_" + "a".repeat(40)));
});
