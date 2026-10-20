/*
 * Loads the tool's own scripts (js/core.js, vendors, analyze, baseline) into Node,
 * so the lab tests exactly the code the web page runs. No browser needed.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.join(__dirname, "..");

function loadTool() {
  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  // Script order is taken from index.html, minus the page and PDF code.
  const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  const scripts = [...html.matchAll(/<script src="(js\/[^"]+)"><\/script>/g)]
    .map((m) => m[1])
    .filter((p) => !/\/(app|pdf)\.js$/.test(p));
  for (const file of scripts) vm.runInContext(fs.readFileSync(path.join(ROOT, file), "utf8"), sandbox, { filename: file });
  return sandbox.TM;
}

module.exports = { loadTool, ROOT };
