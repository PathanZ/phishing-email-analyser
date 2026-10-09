/*
 * Automated checks for the Phishing Email Analyser.
 * Run with:  node tests/run-tests.js
 * Needs nothing installed beyond Node.js. Makes no network requests.
 */
'use strict';

var PEA = require('../js/analyser.js');
var SAMPLES = require('../js/samples.js');

var passed = 0;
var failed = 0;

function check(name, condition, info) {
  if (condition) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (info ? '  →  ' + info : '')); }
}

function fired(result) { return result.findings.map(function (f) { return f.id; }); }

console.log('\nDemo emails land in the expected band');
SAMPLES.forEach(function (s) {
  var r = PEA.analyse(s.text);
  check(s.label + ' → ' + r.level.label + ' (' + r.score + ')', s.expected.indexOf(r.level.key) !== -1,
    'expected ' + s.expected.join(' or ') + '; fired: ' + fired(r).join(', '));
});

console.log('\nEvery rule can fire');
var cases = {
  urgency: 'Please act now, this is urgent.',
  account_threat: 'Your account will be suspended tomorrow.',
  password_request: 'Reply with your current password to continue.',
  mfa_request: 'Please send us the verification code you received.',
  credential_harvest: 'Click the link below to verify your account.',
  payment_request: 'Buy three Google Play gift cards and scratch off the back.',
  bank_change: 'Please note our new bank details for all future payments.',
  invoice: 'Please find attached the outstanding invoice.',
  impersonation: 'Regards, the PayPal Security Team',
  generic_greeting: 'Dear Customer, thank you for banking with us.',
  secrecy: 'Keep this between us for now.',
  display_name_spoof: 'From: PayPal Billing <billing@payments-desk.example>\n\nHello',
  reply_to_mismatch: 'From: Sam <sam@company.example>\nReply-To: sam@other.example\n\nHi',
  return_path_mismatch: 'From: Sam <sam@company.example>\nReturn-Path: <b@mailer.example>\n\nHi',
  spf_fail: 'Authentication-Results: mx.example; spf=fail smtp.mailfrom=x.example\n\nHi',
  spf_softfail: 'Authentication-Results: mx.example; spf=softfail smtp.mailfrom=x.example\n\nHi',
  dkim_fail: 'Authentication-Results: mx.example; dkim=fail header.d=x.example\n\nHi',
  dmarc_fail: 'Authentication-Results: mx.example; dmarc=fail header.from=x.example\n\nHi',
  url_ip: 'Log in here: http://198.51.100.7/portal',
  url_shortener: 'See https://bit.ly/demo-only',
  url_lookalike: 'Go to https://paypa1-resolution.example/case',
  url_suspicious: 'Visit https://account-update-secure-login.example/start',
  misleading_link: '<a href="https://harvest.example/login">https://www.mybank.example/login</a>',
  executable_attachment: 'Attachment: statement.exe',
  unusual_attachment: 'Attachment: Remittance_Advice.pdf.html',
  macro_request: 'If the document looks blank, click Enable Content.'
};
PEA.rules.RULES.forEach(function (rule) {
  var text = cases[rule.id];
  if (!text) { check(rule.id + ' has a test case', false, 'add one to the cases list'); return; }
  var ids = fired(PEA.analyse(text));
  check(rule.id, ids.indexOf(rule.id) !== -1, 'fired: ' + (ids.join(', ') || 'nothing'));
});

console.log('\nThings that should NOT be flagged');
var clean = {
  'code email that says never share': 'Your sign-in code is 482913. Never share this code with anyone.',
  'real Microsoft link': 'Manage your account at https://account.microsoft.com/profile',
  'Node.js mention is not an attachment': 'We rewrote the service in Node.js last year.',
  'ordinary PDF attachment': 'Attached: Meeting_Notes.pdf',
  'email address is not a link': 'Contact jordan@team.example for details.',
  'same-domain reply-to': 'From: Sam <sam@company.example>\nReply-To: billing@mail.company.example\n\nHi',
  'server IP inside a technical header is not a link': 'Authentication-Results: mx.example;\n  spf=pass (sender IP is 203.0.113.9) smtp.mailfrom=a.example\n\nHi',
  'IP address in prose is not a link': 'The printer is at 10.0.0.15 on the office network.',
  'passing authentication':'Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n\nHi'
};
Object.keys(clean).forEach(function (name) {
  var r = PEA.analyse(clean[name]);
  check(name, r.findings.length === 0, 'fired: ' + fired(r).join(', '));
});

console.log('\nScoring behaves');
var repeated = PEA.analyse('Urgent! Urgent! URGENT! act now immediately urgent');
check('a rule only counts once', repeated.score === PEA.rules.RULES.filter(function (r) { return r.id === 'urgency'; })[0].weight, 'score ' + repeated.score);
var maxed = PEA.analyse(SAMPLES[2].text);
check('score never exceeds 100', maxed.score <= 100, 'score ' + maxed.score);
check('empty input is Low Risk with score 0', PEA.analyse('').score === 0);
var marked = PEA.analyse('Please act now.');
check('highlight positions match the text', marked.marks.length === 1 && marked.text.slice(marked.marks[0].start, marked.marks[0].end) === 'act now');

console.log('\nGmail script uses the current rules');
var built = require('child_process').spawnSync(process.execPath, [require('path').join(__dirname, '../tools/build-gmail.js'), '--check']);
check('gmail/PhishCheck.gs is up to date with js/rules.js and js/analyser.js', built.status === 0, 'run: node tools/build-gmail.js');

console.log('\n' + passed + ' passed, ' + failed + ' failed\n');
process.exit(failed ? 1 : 0);
