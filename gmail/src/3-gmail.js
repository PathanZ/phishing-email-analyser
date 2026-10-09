/* ==========================================================================
   Gmail-specific code
   ========================================================================== */

var PROP_LAST_RUN = 'PEA_LAST_RUN_MS';
var PROP_SEEN = 'PEA_SEEN_IDS';
var SEEN_LIMIT = 300;            // remembers recent message IDs to avoid double-checking
var OVERLAP_MS = 15 * 60 * 1000; // re-search 15 minutes back, since Gmail search can lag

/**
 * Run this once. Creates the labels and the timer that checks your inbox.
 */
function setup() {
  getOrCreateLabel_(CONFIG.LABEL_HIGH);
  if (CONFIG.LABEL_SUSPICIOUS_EMAILS) { getOrCreateLabel_(CONFIG.LABEL_SUSPICIOUS); }

  removeTriggers_();
  ScriptApp.newTrigger('checkInbox').timeBased().everyMinutes(CONFIG.CHECK_EVERY_MINUTES).create();

  var props = PropertiesService.getUserProperties();
  if (!props.getProperty(PROP_LAST_RUN)) {
    props.setProperty(PROP_LAST_RUN, String(Date.now() - CONFIG.FIRST_RUN_LOOKBACK_HOURS * 3600 * 1000));
  }
  console.log('Setup complete. Checking your inbox every ' + CONFIG.CHECK_EVERY_MINUTES + ' minutes. Running a first check now...');
  checkInbox();
}

/**
 * Stops the automatic checks. Labels already added are kept.
 */
function uninstall() {
  removeTriggers_();
  PropertiesService.getUserProperties().deleteAllProperties();
  console.log('Uninstalled. No more automatic checks. Your labels and emails are untouched.');
}

/**
 * The main job: check new inbox emails. Runs automatically on the timer,
 * and you can also run it by hand to test.
 */
function checkInbox() {
  var lock = LockService.getUserLock();
  if (!lock.tryLock(1000)) { console.log('Another check is already running; skipping.'); return; }
  try {
    runCheck_();
  } finally {
    lock.releaseLock();
  }
}

function runCheck_() {
  var started = Date.now();
  var props = PropertiesService.getUserProperties();
  var lastRun = Number(props.getProperty(PROP_LAST_RUN)) || (started - CONFIG.FIRST_RUN_LOOKBACK_HOURS * 3600 * 1000);
  var seen = loadSeen_(props);
  var me = (Session.getEffectiveUser().getEmail() || '').toLowerCase();

  var since = Math.floor((lastRun - OVERLAP_MS) / 1000);
  var threads = GmailApp.search('in:inbox after:' + since, 0, 100);

  // Collect messages that arrived after the last run and haven't been checked.
  var queue = [];
  threads.forEach(function (thread) {
    thread.getMessages().forEach(function (msg) {
      var id = msg.getId();
      if (seen.indexOf(id) !== -1) { return; }
      if (msg.getDate().getTime() < lastRun - OVERLAP_MS) { return; }
      queue.push({ thread: thread, msg: msg, id: id, time: msg.getDate().getTime() });
    });
  });
  queue.sort(function (a, b) { return a.time - b.time; }); // oldest first

  var high = getOrCreateLabel_(CONFIG.LABEL_HIGH);
  var susp = CONFIG.LABEL_SUSPICIOUS_EMAILS ? getOrCreateLabel_(CONFIG.LABEL_SUSPICIOUS) : null;
  var alerts = [];
  var checked = 0;
  var newestDone = lastRun;
  var stoppedEarly = false;

  for (var i = 0; i < queue.length; i++) {
    if (checked >= CONFIG.MAX_EMAILS_PER_RUN || (Date.now() - started) / 1000 > CONFIG.MAX_SECONDS_PER_RUN) {
      stoppedEarly = true;
      break;
    }
    var item = queue[i];
    seen.push(item.id);
    newestDone = Math.max(newestDone, item.time);

    if (isOwnMessage_(item.msg, me)) { continue; }

    var text = buildAnalysisText_(item.msg);
    var result = PEA.analyse(text);
    checked++;

    if (result.level.key === 'high') {
      item.thread.addLabel(high);
      if (CONFIG.MOVE_HIGH_RISK_OUT_OF_INBOX) { item.thread.moveToArchive(); }
      if (CONFIG.SEND_ALERT_FOR_HIGH_RISK) { alerts.push(alertEntry_(item, result)); }
    } else if (result.level.key === 'suspicious') {
      if (susp) { item.thread.addLabel(susp); }
      if (CONFIG.SEND_ALERT_FOR_SUSPICIOUS) { alerts.push(alertEntry_(item, result)); }
    }
    console.log(result.level.label + ' (' + result.score + ') — ' + truncate_(item.msg.getSubject(), 80));
  }

  // If we stopped early, resume from the last email we finished next time.
  props.setProperty(PROP_LAST_RUN, String(stoppedEarly ? newestDone : started));
  saveSeen_(props, seen);

  if (alerts.length && me) { sendAlert_(me, alerts); }
  console.log('Checked ' + checked + ' new email(s); ' + alerts.length + ' alert(s).' + (stoppedEarly ? ' More remain; continuing next run.' : ''));
}

/* Turn a Gmail message into the same kind of text you would paste into the website:
   key headers, subject, attachment names, plain-text body, and each HTML link written
   as "visible text <real destination>" so misleading links can be detected. */
function buildAnalysisText_(msg) {
  var lines = [];
  ['From', 'Reply-To', 'Return-Path', 'To', 'Subject', 'Authentication-Results', 'Received-SPF'].forEach(function (name) {
    var value = name === 'Subject' ? msg.getSubject() : safeHeader_(msg, name);
    if (value) { lines.push(name + ': ' + String(value).replace(/\s+/g, ' ').trim()); }
  });
  if (!safeHeader_(msg, 'From')) { lines.unshift('From: ' + msg.getFrom()); }

  var attachments = [];
  try { attachments = msg.getAttachments({ includeInlineImages: false, includeAttachments: true }); } catch (e) { attachments = []; }
  attachments.forEach(function (a) { lines.push('Attachment: ' + a.getName()); });

  lines.push('');
  lines.push(msg.getPlainBody() || '');

  var links = htmlLinks_(msg.getBody() || '');
  if (links.length) {
    lines.push('');
    lines.push('Links in this email:');
    links.forEach(function (l) { lines.push(l); });
  }
  return lines.join('\n');
}

function htmlLinks_(html) {
  var out = [];
  var re = /<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a\s*>/gi;
  var m;
  while ((m = re.exec(html)) !== null && out.length < 60) {
    var href = m[1].replace(/&amp;/gi, '&').trim();
    if (!/^(https?|hxxps?):\/\//i.test(href)) { continue; }
    var shown = m[2].replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/\s+/g, ' ').trim();
    out.push('<a href="' + href.replace(/"/g, '%22') + '">' + (shown || 'link') + '</a>');
  }
  return out;
}

function safeHeader_(msg, name) {
  try { return msg.getHeader(name) || ''; } catch (e) { return ''; }
}

/* Skip this tool's own alert emails (and anything you sent yourself). */
function isOwnMessage_(msg, me) {
  if (!me) { return false; }
  var from = String(msg.getFrom() || '').toLowerCase();
  var fromMe = from.indexOf('<' + me + '>') !== -1 || from === me;
  return fromMe && String(msg.getSubject() || '').indexOf(CONFIG.ALERT_SUBJECT_PREFIX) === 0;
}

/* The alert lists reasons but deliberately never includes links, attachment
   names or quoted text from the suspicious email, so nothing dangerous can be
   clicked from the alert itself. */
function alertEntry_(item, result) {
  return {
    level: result.level.label,
    score: result.score,
    from: cleanSender_(item.msg.getFrom()),
    subject: truncate_(item.msg.getSubject() || '(no subject)', 120),
    date: item.msg.getDate(),
    link: item.thread.getPermalink(),
    reasons: result.findings.map(function (f) { return '+' + f.points + '  ' + f.title; })
  };
}

function sendAlert_(me, alerts) {
  var count = alerts.length;
  var subject = CONFIG.ALERT_SUBJECT_PREFIX + ' ' + count + (count === 1 ? ' email needs' : ' emails need') + ' a careful look';
  var text = [];
  var html = ['<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.5;color:#16202b">'];
  html.push('<p>The Phishing Email Analyser flagged ' + count + ' new email' + (count === 1 ? '' : 's') + '. Don\'t click links or open attachments in ' + (count === 1 ? 'it' : 'them') + ' until you\'ve verified the sender another way.</p>');
  alerts.forEach(function (a) {
    text.push(a.level + ' (' + a.score + '/100)\nFrom: ' + a.from + '\nSubject: ' + a.subject + '\nWhy:\n  ' + a.reasons.join('\n  ') + '\nOpen in Gmail: ' + a.link + '\n');
    html.push('<div style="border-left:4px solid ' + (a.level === 'High Risk' ? '#b92236' : '#c5850e') + ';padding:6px 12px;margin:14px 0">'
      + '<b>' + escapeHtml_(a.level) + ' — ' + a.score + '/100</b><br>'
      + 'From: ' + escapeHtml_(a.from) + '<br>Subject: ' + escapeHtml_(a.subject)
      + '<ul style="margin:6px 0;padding-left:18px">' + a.reasons.map(function (r) { return '<li>' + escapeHtml_(r) + '</li>'; }).join('') + '</ul>'
      + '<a href="' + a.link + '">Open this email in Gmail</a></div>');
  });
  var foot = 'This is an educational triage tool: it flags warning signs and cannot prove an email is malicious or safe. Verify important messages through the organisation\'s official website, app or a phone number you already know.';
  text.push(foot);
  html.push('<p style="color:#566473;font-size:12px">' + foot + '</p></div>');
  GmailApp.sendEmail(me, subject, text.join('\n'), { htmlBody: html.join(''), name: 'Phish Check' });
}

/* Show the sender's display name and address, with the address made unclickable. */
function cleanSender_(from) {
  return String(from || '').replace(/\./g, '[.]').replace(/@/g, ' [at] ');
}

function escapeHtml_(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function truncate_(s, n) {
  s = String(s || '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function getOrCreateLabel_(name) {
  return GmailApp.getUserLabelByName(name) || GmailApp.createLabel(name);
}

function removeTriggers_() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (t.getHandlerFunction() === 'checkInbox') { ScriptApp.deleteTrigger(t); }
  });
}

function loadSeen_(props) {
  try { return JSON.parse(props.getProperty(PROP_SEEN) || '[]'); } catch (e) { return []; }
}

function saveSeen_(props, seen) {
  props.setProperty(PROP_SEEN, JSON.stringify(seen.slice(-SEEN_LIMIT)));
}

/**
 * Explains why recent emails were labelled: lists each warning sign and its
 * points in the log. Web addresses are written with [.] so nothing in the
 * log is clickable. Changes nothing in your inbox.
 */
function explainFlagged() {
  var query = '(label:"' + CONFIG.LABEL_HIGH + '" OR label:"' + CONFIG.LABEL_SUSPICIOUS + '") newer_than:3d';
  var threads = GmailApp.search(query, 0, 30);
  if (!threads.length) { console.log('No labelled emails in the last 3 days.'); return; }
  threads.forEach(function (thread) {
    var msgs = thread.getMessages();
    var msg = msgs[msgs.length - 1];
    var r = PEA.analyse(buildAnalysisText_(msg));
    var lines = [r.level.label + ' (' + r.score + ') — ' + truncate_(msg.getSubject(), 70), '  From: ' + defang_(msg.getFrom())];
    r.findings.forEach(function (f) {
      var e = f.evidence[0] || {};
      var example = e.detail || ('"' + String(e.text || '').replace(/\s+/g, ' ').trim() + '"');
      lines.push('  +' + f.points + ' ' + f.title + ' — ' + defang_(truncate_(example, 110)));
    });
    console.log(lines.join('\n'));
  });
}

/**
 * After the rules change: re-checks emails labelled in the last 7 days and
 * corrects their labels (adds, changes or removes them). Sends no alerts.
 */
function recheckLabelled() {
  var high = getOrCreateLabel_(CONFIG.LABEL_HIGH);
  var susp = getOrCreateLabel_(CONFIG.LABEL_SUSPICIOUS);
  var query = '(label:"' + CONFIG.LABEL_HIGH + '" OR label:"' + CONFIG.LABEL_SUSPICIOUS + '") newer_than:7d';
  var threads = GmailApp.search(query, 0, 100);
  var changed = 0;
  threads.forEach(function (thread) {
    var worst = 'low';
    thread.getMessages().forEach(function (msg) {
      var level = PEA.analyse(buildAnalysisText_(msg)).level.key;
      if (level === 'high' || (level === 'suspicious' && worst === 'low')) { worst = level; }
    });
    var before = thread.getLabels().map(function (l) { return l.getName(); });
    thread.removeLabel(high);
    thread.removeLabel(susp);
    if (worst === 'high') { thread.addLabel(high); }
    else if (worst === 'suspicious' && CONFIG.LABEL_SUSPICIOUS_EMAILS) { thread.addLabel(susp); }
    var nowName = worst === 'high' ? CONFIG.LABEL_HIGH : (worst === 'suspicious' ? CONFIG.LABEL_SUSPICIOUS : null);
    var hadName = before.indexOf(CONFIG.LABEL_HIGH) !== -1 ? CONFIG.LABEL_HIGH : CONFIG.LABEL_SUSPICIOUS;
    if (nowName !== hadName) {
      changed++;
      console.log((nowName ? 'Now ' + nowName.split('/').pop() : 'Label removed') + ' — ' + truncate_(thread.getFirstMessageSubject(), 80));
    }
  });
  console.log('Re-checked ' + threads.length + ' labelled email(s); ' + changed + ' changed.');
}

function defang_(s) {
  return String(s || '').replace(/https?:\/\//gi, '').replace(/\./g, '[.]');
}

/**
 * Optional: runs the six fictional demo emails through the analyser and
 * prints the results in the log, without touching your inbox.
 */
function testWithDemoEmails() {
  PEA_SAMPLES.forEach(function (s) {
    var r = PEA.analyse(s.text);
    console.log(s.label + ': ' + r.level.label + ' (' + r.score + ') — ' + r.findings.map(function (f) { return f.title; }).join('; '));
  });
}
