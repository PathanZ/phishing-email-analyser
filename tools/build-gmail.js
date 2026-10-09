/*
 * Builds gmail/PhishCheck.gs — ONE file to paste into Google Apps Script.
 * It joins the settings, the website's own rules and engine (unchanged),
 * the demo emails and the Gmail code, so both versions always use identical rules.
 *
 * Run from the project folder:  node tools/build-gmail.js
 * Add --check to only verify the file is up to date (used by the tests).
 */
'use strict';

var fs = require('fs');
var path = require('path');

var root = path.join(__dirname, '..');
var parts = [
  'gmail/src/1-settings.js',
  'js/rules.js',
  'js/analyser.js',
  'js/samples.js',
  'gmail/src/3-gmail.js'
];

var out = parts.map(function (p) {
  var body = fs.readFileSync(path.join(root, p), 'utf8').replace(/\s+$/, '');
  return p.indexOf('gmail/') === 0 ? body : '/* ---------- from ' + p + ' ---------- */\n' + body;
}).join('\n\n') + '\n';

var target = path.join(root, 'gmail/PhishCheck.gs');

if (process.argv.indexOf('--check') !== -1) {
  var current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '';
  if (current !== out) {
    console.error('gmail/PhishCheck.gs is out of date. Run: node tools/build-gmail.js');
    process.exit(1);
  }
  console.log('gmail/PhishCheck.gs is up to date.');
} else {
  fs.writeFileSync(target, out);
  console.log('Wrote gmail/PhishCheck.gs (' + out.split('\n').length + ' lines).');
}
