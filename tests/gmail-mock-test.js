/*
 * Tests the Gmail script (gmail/PhishCheck.gs) against a pretend inbox.
 * Google's Gmail, timer and storage services are replaced with simple
 * stand-ins, so this runs anywhere with Node.js and touches no real email.
 *
 * Run with:  node tests/gmail-mock-test.js
 */
'use strict';

var fs = require('fs');
var path = require('path');
var vm = require('vm');

var SAMPLES = require('../js/samples.js');
var ME = 'zaid.test@mail.example';
var NOW = Date.now();

var passed = 0, failed = 0;
function check(name, ok, info) {
  if (ok) { passed++; console.log('  PASS  ' + name); }
  else { failed++; console.log('  FAIL  ' + name + (info ? '  →  ' + info : '')); }
}

/* ---------------- Pretend Gmail ---------------- */

var labels = {};
var sent = [];
var threads = [];
var idCounter = 0;

function makeLabel(name) {
  return { name: name, getName: function () { return name; } };
}

function makeMessage(spec) {
  var id = 'm' + (++idCounter);
  return {
    getId: function () { return id; },
    getDate: function () { return new Date(spec.time); },
    getFrom: function () { return spec.headers.From || ''; },
    getSubject: function () { return spec.headers.Subject || ''; },
    getHeader: function (n) { return spec.headers[n] || ''; },
    getAttachments: function () { return (spec.attachments || []).map(function (a) { return { getName: function () { return a; } }; }); },
    getPlainBody: function () { return spec.body; },
    getBody: function () { return spec.html || spec.body.replace(/\n/g, '<br>'); }
  };
}

function addThread(spec) {
  var t = {
    id: 't' + threads.length,
    labels: [],
    inInbox: true,
    messages: [makeMessage(spec)],
    getMessages: function () { return this.messages; },
    addLabel: function (l) { if (this.labels.indexOf(l.name) === -1) { this.labels.push(l.name); } },
    removeLabel: function (l) { this.labels = this.labels.filter(function (n) { return n !== l.name; }); },
    getLabels: function () { return this.labels.map(makeLabel); },
    getFirstMessageSubject: function () { return this.messages[0].getSubject(); },
    moveToArchive: function () { this.inInbox = false; },
    getPermalink: function () { return 'https://mail.google.com/mail/#all/' + this.id; }
  };
  threads.push(t);
  return t;
}

/* Turn a demo email (headers + blank line + body) into a pretend Gmail message. */
function fromSample(text, minutesAgo, extra) {
  var split = text.indexOf('\n\n');
  var headerPart = split === -1 ? '' : text.slice(0, split);
  var body = split === -1 ? text : text.slice(split + 2);
  var headers = {};
  var lastName = null;
  headerPart.split('\n').forEach(function (line) {
    var m = /^([A-Za-z-]+):\s*(.*)$/.exec(line);
    if (m) { lastName = m[1]; headers[lastName] = m[2]; }
    else if (lastName && /^\s+/.test(line)) { headers[lastName] += ' ' + line.trim(); }
  });
  var spec = { headers: headers, body: body, time: NOW - minutesAgo * 60000 };
  Object.keys(extra || {}).forEach(function (k) { spec[k] = extra[k]; });
  return spec;
}

var store = {};
var triggers = [];

var sandbox = {
  console: { log: function () {} },
  Date: Date, JSON: JSON, Math: Math, String: String, Number: Number, Object: Object, RegExp: RegExp, Array: Array, Error: Error,
  GmailApp: {
    search: function (q) {
      var after = Number((/after:(\d+)/.exec(q) || [])[1] || 0) * 1000;
      return threads.filter(function (t) {
        return t.inInbox && t.messages.some(function (m) { return m.getDate().getTime() >= after; });
      });
    },
    getUserLabelByName: function (n) { return labels[n] || null; },
    createLabel: function (n) { labels[n] = makeLabel(n); return labels[n]; },
    sendEmail: function (to, subject, body, opts) { sent.push({ to: to, subject: subject, body: body, html: opts && opts.htmlBody }); }
  },
  PropertiesService: {
    getUserProperties: function () {
      return {
        getProperty: function (k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
        setProperty: function (k, v) { store[k] = String(v); },
        deleteAllProperties: function () { store = {}; }
      };
    }
  },
  ScriptApp: {
    newTrigger: function (fn) {
      var b = { timeBased: function () { return b; }, everyMinutes: function (n) { b.n = n; return b; },
        create: function () { var t = { getHandlerFunction: function () { return fn; }, every: b.n }; triggers.push(t); return t; } };
      return b;
    },
    getProjectTriggers: function () { return triggers.slice(); },
    deleteTrigger: function (t) { triggers = triggers.filter(function (x) { return x !== t; }); }
  },
  LockService: { getUserLock: function () { return { tryLock: function () { return true; }, releaseLock: function () {} }; } },
  Session: { getEffectiveUser: function () { return { getEmail: function () { return ME; } }; } }
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../gmail/PhishCheck.gs'), 'utf8'), sandbox, { filename: 'PhishCheck.gs' });

/* ---------------- Build the inbox ---------------- */

var byId = {};
SAMPLES.forEach(function (s, i) { byId[s.id] = addThread(fromSample(s.text, 30 + i)); });

var newsletter = addThread({
  time: NOW - 20 * 60000,
  headers: {
    From: 'Harbour Coffee Co. <news@harbourcoffee.example>',
    Subject: 'Our autumn blends are here',
    'Authentication-Results': 'mx.google.com; dkim=pass header.i=@harbourcoffee.example; spf=pass; dmarc=pass header.from=harbourcoffee.example'
  },
  body: 'Hi Zaid,\n\nOur autumn blends just landed. Visit www.harbourcoffee.example to see them.\n\nHarbour Coffee Co.',
  html: '<p>Our autumn blends just landed.</p><a href="https://harbourcoffee.us1.list-manage.com/track/click?u=1">www.harbourcoffee.example</a>'
});

var htmlTrick = addThread({
  time: NOW - 15 * 60000,
  headers: { From: 'Accounts <billing@payments-portal.example>', Subject: 'Statement available' },
  body: 'Your statement is available. View it at https://www.mybank.example/statements',
  html: '<p>Your statement is available.</p><p><a href="https://collect.payments-portal.example/login">https://www.mybank.example/statements</a></p>'
});

var attachmentOnly = addThread({
  time: NOW - 10 * 60000,
  headers: { From: 'Jordan <jordan@supplier.example>', Subject: 'Documents' },
  body: 'Hi, please see the attached documents.',
  attachments: ['Scan_0921.pdf', 'Viewer.js']
});

var ownAlert = addThread({
  time: NOW - 5 * 60000,
  headers: { From: 'Phish Check <' + ME + '>', Subject: '[Phish Check] 3 emails need a careful look' },
  body: 'Asks for your password. Asks for a verification (MFA) code. Shortened link. Gift cards. Urgent.'
});

var oldEmail = addThread(fromSample(SAMPLES[0].text, 60 * 48));

/* ---------------- Run ---------------- */

console.log('\nFirst run (setup)');
sandbox.setup();

check('timer created to run checkInbox every 5 minutes', triggers.length === 1 && triggers[0].getHandlerFunction() === 'checkInbox' && triggers[0].every === 5);
check('both labels created', !!labels['Phish Check/High Risk'] && !!labels['Phish Check/Suspicious']);

function levelOf(t) {
  if (t.labels.indexOf('Phish Check/High Risk') !== -1) { return 'high'; }
  if (t.labels.indexOf('Phish Check/Suspicious') !== -1) { return 'suspicious'; }
  return 'low';
}

SAMPLES.forEach(function (s) {
  var got = levelOf(byId[s.id]);
  check(s.label + ' labelled ' + got, s.expected.indexOf(got) !== -1, 'expected ' + s.expected.join(' or '));
});
check('newsletter with tracking link is not labelled', levelOf(newsletter) === 'low', newsletter.labels.join(', '));
check('HTML link that lies about its destination is flagged', levelOf(htmlTrick) !== 'low', htmlTrick.labels.join(', '));
check('executable attachment (from Gmail attachment list) is flagged', levelOf(attachmentOnly) !== 'low', attachmentOnly.labels.join(', '));
check('its own alert email is skipped', levelOf(ownAlert) === 'low', ownAlert.labels.join(', '));
check('emails older than the look-back window are skipped', levelOf(oldEmail) === 'low');
check('nothing was moved out of the inbox (default setting)', threads.every(function (t) { return t.inInbox; }));

check('exactly one alert email sent', sent.length === 1, sent.length + ' sent');
var alert = sent[0] || { body: '', html: '', subject: '' };
check('alert goes to you', alert.to === ME);
var highCount = threads.filter(function (t) { return levelOf(t) === 'high'; }).length;
check('alert lists every High Risk email (' + highCount + ')', alert.subject.indexOf(String(highCount)) !== -1, alert.subject);
var linkFree = !/192\.0\.2|verify-storage|northline-delivery|files-portal|freemail\.example|\.exe|Viewer\.js|http:\/\//i.test(alert.body + alert.html);
check('alert contains no links, addresses or file names from the suspicious emails', linkFree);
check('alert includes the educational disclaimer', /cannot prove/.test(alert.body));

console.log('\nSecond run (nothing new)');
sent.length = 0;
var before = JSON.stringify(threads.map(function (t) { return t.labels; }));
sandbox.checkInbox();
check('no duplicate alert when nothing new arrived', sent.length === 0);
check('labels unchanged', JSON.stringify(threads.map(function (t) { return t.labels; })) === before);

console.log('\nThird run (a new phishing email arrives)');
var late = addThread(fromSample(SAMPLES[2].text, 0));
sandbox.checkInbox();
check('new email is checked and labelled', levelOf(late) === 'high');
check('one new alert for the new email only', sent.length === 1 && /1 email needs/.test(sent[0].subject), sent.map(function (s) { return s.subject; }).join(' | '));

console.log('\nOptional setting: move High Risk out of the inbox');
sandbox.CONFIG.MOVE_HIGH_RISK_OUT_OF_INBOX = true;
var moved = addThread(fromSample(SAMPLES[4].text, 0));
sandbox.checkInbox();
check('High Risk email archived (not deleted) when the setting is on', !moved.inInbox && levelOf(moved) === 'high' && threads.indexOf(moved) !== -1);

console.log('\nexplainFlagged');
var logged = [];
sandbox.console.log = function (x) { logged.push(String(x)); };
sandbox.GmailApp.search = function () { return threads.filter(function (t) { return t.labels.length; }); };
sandbox.explainFlagged();
sandbox.console.log = function () {};
var out = logged.join('\n');
check('explains each labelled email with points', /\+\d+ /.test(out) && out.indexOf('High Risk') !== -1);
check('web addresses in the explanation are not clickable', !/https?:\/\//.test(out) && !/192\.0\.2/.test(out) && /\[\.\]/.test(out));

console.log('\nrecheckLabelled');
newsletter.labels.push('Phish Check/Suspicious');      // pretend an older rule version flagged it
var sentBefore = sent.length;
sandbox.recheckLabelled();
check('wrongly labelled email has its label removed', levelOf(newsletter) === 'low', newsletter.labels.join(', '));
check('genuine High Risk email keeps its label', levelOf(byId.obvious) === 'high');
check('recheck sends no alerts', sent.length === sentBefore);

console.log('\nUninstall');
sandbox.uninstall();
check('timer removed', triggers.length === 0);
check('labels kept', levelOf(byId.obvious) === 'high');

console.log('\n' + passed + ' passed, ' + failed + ' failed\n');
process.exit(failed ? 1 : 0);
