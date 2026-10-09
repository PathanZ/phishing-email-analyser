/*
 * Phishing Email Analyser — analysis engine
 * ------------------------------------------
 * Takes the pasted email text, runs every rule from rules.js against it and
 * returns an explainable result: which rules fired, the exact text that
 * triggered each one, and the points each one added.
 *
 * It never sends anything anywhere. It only reads the text it is given.
 * Works unchanged in a browser, in Node.js and in Google Apps Script.
 */
(function (root) {
  'use strict';

  var R = root.PEA_RULES || (typeof require === 'function' ? require('./rules.js') : null);
  if (!R) { throw new Error('rules.js must be loaded before analyser.js'); }

  var MAX_INPUT = 200000;          // characters; protects slow devices
  var MAX_EVIDENCE_PER_RULE = 6;   // examples shown per warning sign

  /* ------------------------------------------------------------------ */
  /* Small helpers                                                       */
  /* ------------------------------------------------------------------ */

  function severityFor(weight) {
    if (weight >= 20) { return 'high'; }
    if (weight >= 12) { return 'medium'; }
    return 'low';
  }

  function levelFor(score) {
    if (score >= R.THRESHOLDS.high) { return { key: 'high', label: 'High Risk' }; }
    if (score >= R.THRESHOLDS.suspicious) { return { key: 'suspicious', label: 'Suspicious' }; }
    return { key: 'low', label: 'Low Risk' };
  }

  /* Replace the characters in the given ranges with spaces (keeping line
     breaks), so phrase rules don't match inside links, addresses or
     technical header lines — while every position still lines up with the
     original text for highlighting. */
  function mask(text, ranges) {
    if (!ranges.length) { return text; }
    var chars = text.split('');
    ranges.forEach(function (r) {
      for (var i = r.start; i < r.end && i < chars.length; i++) {
        if (chars[i] !== '\n') { chars[i] = ' '; }
      }
    });
    return chars.join('');
  }

  /* "mail.login.example.co.uk" -> "example.co.uk". The registered domain is
     the part that shows who actually owns a website. This is a close
     approximation that needs no external list. */
  var SECOND_LEVEL = ['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'gc', 'ab', 'bc', 'mb', 'nb', 'nl', 'ns', 'nt', 'nu', 'on', 'pe', 'qc', 'sk', 'yk'];
  function orgDomain(host) {
    if (!host) { return ''; }
    host = host.toLowerCase().replace(/\.$/, '');
    if (isIp(host)) { return host; }
    var labels = host.split('.');
    if (labels.length <= 2) { return host; }
    var tld = labels[labels.length - 1];
    var sld = labels[labels.length - 2];
    if (tld.length === 2 && SECOND_LEVEL.indexOf(sld) !== -1) { return labels.slice(-3).join('.'); }
    return labels.slice(-2).join('.');
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:.]+\]$/i.test(host) ||
      /^0x[0-9a-f]{6,8}$/i.test(host) || /^\d{8,10}$/.test(host);
  }

  function ownedBy(host, brand) {
    host = (host || '').toLowerCase();
    return brand.domains.some(function (d) { return host === d || host.slice(-(d.length + 1)) === '.' + d; });
  }

  /* Undo common look-alike swaps: paypa1 -> paypal, rnicrosoft -> microsoft */
  function deconfuse(s) {
    return s.toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w')
      .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't');
  }

  /* Does a domain name contain a brand's name? Returns the brand or null. */
  function brandInHost(host) {
    var variants = [host.toLowerCase(), deconfuse(host)];
    for (var b = 0; b < R.BRANDS.length; b++) {
      var brand = R.BRANDS[b];
      for (var t = 0; t < brand.tokens.length; t++) {
        var token = brand.tokens[t];
        for (var v = 0; v < variants.length; v++) {
          var parts = variants[v].split(/[.\-_]/);
          var joined = parts.join('');
          var hit = token.length >= 6 ? joined.indexOf(token) !== -1 : parts.indexOf(token) !== -1;
          if (hit) { return { brand: brand, confusable: v === 1 && variants[0] !== variants[1] && variants[0].split(/[.\-_]/).join('').indexOf(token) === -1 }; }
        }
      }
    }
    return null;
  }

  /* Does a piece of visible text name a brand? (e.g. the display name) */
  function brandInText(text) {
    var lower = ' ' + text.toLowerCase().replace(/[^a-z0-9]+/g, ' ') + ' ';
    var squashed = lower.replace(/\s+/g, '');
    for (var b = 0; b < R.BRANDS.length; b++) {
      var brand = R.BRANDS[b];
      if (lower.indexOf(' ' + brand.name.toLowerCase() + ' ') !== -1) { return brand; }
      for (var t = 0; t < brand.tokens.length; t++) {
        var token = brand.tokens[t];
        if (token.length >= 6 ? squashed.indexOf(token) !== -1 : lower.indexOf(' ' + token + ' ') !== -1) { return brand; }
      }
    }
    return null;
  }

  /* ------------------------------------------------------------------ */
  /* Headers                                                             */
  /* ------------------------------------------------------------------ */

  var HEADER_LINE = /^(from|reply-to|return-path|sender|to|cc|subject|date|authentication-results|arc-authentication-results|received-spf|received|dkim-signature|arc-seal|arc-message-signature|message-id|mime-version|content-type|content-disposition|content-transfer-encoding|list-unsubscribe|list-unsubscribe-post|delivered-to|x-[a-z0-9-]+):[ \t]*(.*)$/i;
  /* Technical headers that contain words like "pass", "fail" or long codes —
     ignored by the phrase rules so they can't cause false matches. */
  var NOISY = /^(authentication-results|arc-|received|dkim-signature|message-id|mime-version|content-transfer-encoding|list-unsubscribe|delivered-to|x-)/i;

  function extractHeaders(text) {
    var list = [];
    var lines = text.split('\n');
    var offset = 0;
    var current = null;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var lineStart = offset;
      offset += line.length + 1;
      if (current && /^[ \t]+\S/.test(line)) {          // folded continuation line
        current.value += ' ' + line.trim();
        current.end = lineStart + line.length;
        continue;
      }
      current = null;
      var m = HEADER_LINE.exec(line);
      if (m) {
        current = { name: m[1].toLowerCase(), value: m[2].trim(), start: lineStart, end: lineStart + line.length,
          valueStart: lineStart + line.length - m[2].length, firstLineEnd: lineStart + line.length };
        list.push(current);
      }
    }
    function first(name) { for (var k = 0; k < list.length; k++) { if (list[k].name === name) { return list[k]; } } return null; }
    function all(name) { return list.filter(function (h) { return h.name === name; }); }
    return {
      list: list, first: first, all: all,
      noisyRanges: list.filter(function (h) { return NOISY.test(h.name); }).map(function (h) { return { start: h.start, end: h.end }; })
    };
  }

  function parseAddress(value) {
    if (!value) { return null; }
    var angle = /<\s*([^<>\s]*)\s*>/.exec(value);
    var address = angle ? angle[1] : ((/[^\s<>"',;]+@[^\s<>"',;]+/.exec(value) || [])[0] || '');
    var name = angle ? value.slice(0, angle.index).replace(/["']/g, '').trim() : '';
    address = address.replace(/^mailto:/i, '');
    var domain = address.indexOf('@') !== -1 ? address.split('@').pop().toLowerCase().replace(/[>.,;]+$/, '') : '';
    return { name: name, address: address, domain: domain, org: orgDomain(domain) };
  }

  /* Find "spf=fail" style results inside authentication headers. */
  function readAuth(headers, text) {
    var sources = headers.all('authentication-results');
    if (!sources.length) { sources = headers.all('arc-authentication-results'); }
    function find(mech) {
      var results = [];
      sources.forEach(function (h) {
        var re = new RegExp('\\b' + mech + '=([a-z]+)', 'gi');
        var segment = text.slice(h.start, h.end);
        var m;
        while ((m = re.exec(segment)) !== null) {
          results.push({ result: m[1].toLowerCase(), start: h.start + m.index, end: h.start + m.index + m[0].length, text: m[0] });
        }
      });
      return results;
    }
    var spf = find('spf');
    if (!spf.length) {
      var rs = headers.first('received-spf');
      if (rs) {
        var word = (/^([a-z]+)/i.exec(rs.value) || [])[1];
        if (word) { spf = [{ result: word.toLowerCase(), start: rs.start, end: rs.firstLineEnd, text: text.slice(rs.start, rs.firstLineEnd) }]; }
      }
    }
    var dkim = find('dkim');
    var dmarc = find('dmarc');

    function summarise(arr, isDkim) {
      if (!arr.length) { return null; }
      if (isDkim) {
        var pass = arr.filter(function (r) { return r.result === 'pass'; });
        if (pass.length) { return pass[0]; }
        var bad = arr.filter(function (r) { return r.result === 'fail' || r.result === 'permerror'; });
        return bad.length ? bad[0] : arr[0];
      }
      return arr[0];
    }
    return { spf: summarise(spf), dkim: summarise(dkim, true), dmarc: summarise(dmarc) };
  }

  /* ------------------------------------------------------------------ */
  /* Links                                                               */
  /* ------------------------------------------------------------------ */

  var SCHEME_URL = /\b(?:https?|hxxps?):\/\/[^\s<>"'`]+|\bwww\.[^\s<>"'`]+/gi;
  /* Bare links like "verify-account.example/login" (no http://). The first
     group stops us matching the middle of an email address or longer URL. */
  var BARE_URL = /(^|[^@\w.\/-])((?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,}(?::\d+)?\/[^\s<>"'`]*|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\/[^\s<>"'`]*)/gi;

  function cleanTrailing(u) { return u.replace(/[.,;:!?)\]}>'"*]+$/, ''); }

  function parseUrl(raw) {
    var s = raw.replace(/^hxxp/i, 'http');
    var m = /^(?:([a-z][a-z0-9+.-]*):\/\/)?([^\/?#]*)(.*)$/i.exec(s);
    var scheme = (m[1] || '').toLowerCase();
    var authority = m[2] || '';
    var hostPort = authority.split('@').pop();
    var host = hostPort.charAt(0) === '[' ? hostPort.replace(/\](:\d+)?$/, ']') : hostPort.replace(/:\d+$/, '');
    host = host.toLowerCase().replace(/\.$/, '');
    return { raw: raw, scheme: scheme, host: host, org: orgDomain(host), hasAt: authority.indexOf('@') !== -1, path: m[3] || '' };
  }

  function extractUrls(text) {
    var found = [];
    var m;
    SCHEME_URL.lastIndex = 0;
    while ((m = SCHEME_URL.exec(text)) !== null) {
      var u = cleanTrailing(m[0]);
      found.push(Object.assign(parseUrl(u), { start: m.index, end: m.index + u.length }));
    }
    BARE_URL.lastIndex = 0;
    while ((m = BARE_URL.exec(text)) !== null) {
      var start = m.index + m[1].length;
      var bare = cleanTrailing(m[2]);
      var end = start + bare.length;
      var overlaps = found.some(function (f) { return start < f.end && end > f.start; });
      if (!overlaps && bare.length > 4) { found.push(Object.assign(parseUrl(bare), { start: start, end: end })); }
    }
    found.sort(function (a, b) { return a.start - b.start; });
    return found.filter(function (u) { return u.host; });
  }

  function suspiciousReasons(u) {
    var reasons = [];
    var tld = u.host.split('.').pop();
    var orgLabel = u.org.split('.')[0] || '';
    var ownedByBrand = R.BRANDS.some(function (b) { return ownedBy(u.host, b); });
    if (u.hasAt) { reasons.push('contains "@" — a browser ignores everything before it, hiding the real site'); }
    if (u.scheme === 'http' && !isIp(u.host)) { reasons.push('uses unencrypted http://'); }
    if (R.RISKY_TLDS.indexOf(tld) !== -1) { reasons.push('ends in ".' + tld + '", a domain ending often used for abuse'); }
    if ((u.host.match(/-/g) || []).length >= 3) { reasons.push('has many hyphens in the domain'); }
    if (u.host.replace(/^www\./, '').split('.').length >= 5) { reasons.push('has an unusually long chain of sub-domains'); }
    if (!ownedByBrand && !isIp(u.host)) {
      var lure = R.LURE_WORDS.filter(function (w) { return orgLabel.indexOf(w.replace('-', '')) !== -1 || orgLabel.indexOf(w) !== -1; });
      if (lure.length) { reasons.push('registered domain contains official-sounding words ("' + lure.slice(0, 2).join('", "') + '")'); }
    }
    var fileExt = (/\.([a-z0-9]{2,12})(?:[?#]|$)/i.exec(u.path) || [])[1];
    if (fileExt && R.ATTACHMENT_TYPES.executable.concat(R.ATTACHMENT_TYPES.diskImage).indexOf(fileExt.toLowerCase()) !== -1) {
      reasons.push('links straight to a .' + fileExt.toLowerCase() + ' program or disk-image file');
    }
    return reasons;
  }

  /* Links whose visible text shows a different destination. */
  function misleadingLinks(text) {
    var out = [];
    function stripTags(s) {
      return s.replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/\s+/g, ' ').trim();
    }
    function looksLikeUrl(s) { return /^(https?:\/\/)?(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}(:\d+)?(\/\S*)?$/i.test(s); }
    function compare(shown, href, start, end, matchText) {
      if (!/^(https?|hxxps?):\/\//i.test(href)) { return; }
      var target = parseUrl(href);
      if (!target.host) { return; }
      if (looksLikeUrl(shown)) {
        var shownHost = parseUrl(/^[a-z]+:\/\//i.test(shown) ? shown : 'http://' + shown).host;
        if (shownHost && orgDomain(shownHost) !== target.org) {
          out.push({ text: matchText, start: start, end: end, detail: 'Shows "' + shownHost + '" but actually goes to "' + target.host + '"' });
        }
        return;
      }
      var brand = brandInText(shown);
      if (brand && !ownedBy(target.host, brand)) {
        out.push({ text: matchText, start: start, end: end, detail: 'Link text mentions ' + brand.name + ' but goes to "' + target.host + '"' });
      }
    }
    var m;
    var anchor = /<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a\s*>/gi;
    while ((m = anchor.exec(text)) !== null) { compare(stripTags(m[2]), m[1].trim(), m.index, m.index + m[0].length, m[0]); }
    var markdown = /\[([^\]\n]{1,200})\]\(((?:https?|hxxps?):\/\/[^\s)]+)\)/gi;
    while ((m = markdown.exec(text)) !== null) { compare(m[1].trim(), m[2], m.index, m.index + m[0].length, m[0]); }
    /* Plain-text copies often look like:  https://shown.example <https://real.example> */
    var angle = /((?:https?:\/\/|www\.)[^\s<>]+)\s*<((?:https?|hxxps?):\/\/[^\s<>]+)>/gi;
    while ((m = angle.exec(text)) !== null) { compare(m[1], m[2], m.index, m.index + m[0].length, m[0]); }
    /* "Click here <https://…>" style: visible words followed by the real address */
    var wordsAngle = /([A-Za-z][A-Za-z0-9 '&.-]{2,60}?)\s*<((?:https?|hxxps?):\/\/[^\s<>]+)>/g;
    while ((m = wordsAngle.exec(text)) !== null) {
      if (/(?:https?:\/\/|www\.)/i.test(m[1])) { continue; }
      var words = m[1].trim();
      var brand = brandInText(words);
      var target = parseUrl(m[2]);
      if (brand && target.host && !ownedBy(target.host, brand)) {
        out.push({ text: m[0], start: m.index, end: m.index + m[0].length, detail: 'Link text mentions ' + brand.name + ' but goes to "' + target.host + '"' });
      }
    }
    return out;
  }

  /* ------------------------------------------------------------------ */
  /* Attachments                                                         */
  /* ------------------------------------------------------------------ */

  var FILE_NAME = /(^|[\s"'(\[:=*])([^\s"'<>\/\\:*?|()\[\]]{1,150}?\.([a-z0-9]{1,12}))(?=$|[\s"'),;:\]!?*]|\.(?:\s|$))/gim;
  var NOT_FILES = ['node.js', 'vue.js', 'next.js', 'react.js', 'three.js', 'd3.js', 'express.js', 'nuxt.js', 'angular.js', 'ember.js', 'chart.js', 'p5.js'];
  var DOUBLE_EXT = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|rtf|odt)\.([a-z0-9]{2,12})$/i;

  function extractAttachments(masked, original) {
    var T = R.ATTACHMENT_TYPES;
    var mentionsArchivePassword = /\b(password|passcode|pwd)\b[^.\n]{0,40}\b(attach\w*|archive|zip|file|document|open)\b|\b(attach\w*|archive|zip)\b[^.\n]{0,40}\b(password|passcode)\b/i.test(masked);
    var files = [];
    var seen = {};
    var m;
    FILE_NAME.lastIndex = 0;
    while ((m = FILE_NAME.exec(masked)) !== null) {
      var name = m[2];
      var ext = m[3].toLowerCase();
      var lower = name.toLowerCase();
      if (name.indexOf('@') !== -1 || ext === 'com' || NOT_FILES.indexOf(lower) !== -1 || /^\.+/.test(name)) { continue; }
      var start = m.index + m[1].length;
      var item = { name: original.slice(start, start + name.length), ext: ext, start: start, end: start + name.length, executable: null, unusual: [] };
      if (T.executable.indexOf(ext) !== -1) { item.executable = '.' + ext + ' files run code when opened'; }
      var dbl = DOUBLE_EXT.exec(name);
      if (dbl && dbl[1].toLowerCase() !== ext) { item.unusual.push('double extension — it looks like a .' + dbl[1].toLowerCase() + ' but is really a .' + ext); }
      if (/‮/.test(name)) { item.unusual.push('contains a hidden right-to-left character that disguises the real extension'); }
      if (T.macro.indexOf(ext) !== -1) { item.unusual.push('macro-enabled Office file (.' + ext + ') that can contain programs'); }
      if (T.diskImage.indexOf(ext) !== -1) { item.unusual.push('disk image (.' + ext + ') — often used to smuggle malware past email filters'); }
      if (T.webPage.indexOf(ext) !== -1) { item.unusual.push('web-page attachment (.' + ext + ') that can show a fake sign-in form'); }
      if (T.archive.indexOf(ext) !== -1 && mentionsArchivePassword) { item.unusual.push('password-protected archive (.' + ext + ') — security scanners can\'t look inside'); }
      var known = item.executable || item.unusual.length || [T.document, T.archive].some(function (list) { return list.indexOf(ext) !== -1; });
      if (!known) { continue; }
      if (!seen[lower]) { seen[lower] = true; files.push(item); }
    }
    return files;
  }

  /* ------------------------------------------------------------------ */
  /* Structural checks (rules with type: 'check')                        */
  /* ------------------------------------------------------------------ */

  var CHECKS = {
    displayName: function (c) {
      var from = c.sender.from;
      if (!from || !from.domain) { return []; }
      var out = [];
      var h = c.headers.first('from');
      var ev = { text: c.text.slice(h.valueStart, h.firstLineEnd), start: h.valueStart, end: h.firstLineEnd };
      var brand = from.name ? brandInText(from.name) : null;
      if (brand && !ownedBy(from.domain, brand)) {
        out.push(Object.assign({}, ev, { detail: 'Name says "' + from.name + '" (' + brand.name + '), but the address is @' + from.domain }));
      }
      var embedded = /[^\s@<>"']+@([a-z0-9.-]+\.[a-z]{2,})/i.exec(from.name || '');
      if (embedded && orgDomain(embedded[1]) !== from.org) {
        out.push(Object.assign({}, ev, { detail: 'Name contains the address @' + embedded[1].toLowerCase() + ', but the real address is @' + from.domain }));
      }
      return out;
    },
    replyTo: function (c) {
      var from = c.sender.from, rt = c.sender.replyTo;
      if (!from || !rt || !from.org || !rt.org || from.org === rt.org) { return []; }
      var h = c.headers.first('reply-to');
      return [{ text: c.text.slice(h.valueStart, h.firstLineEnd), start: h.valueStart, end: h.firstLineEnd,
        detail: 'Replies go to @' + rt.domain + ', but the email says it is from @' + from.domain }];
    },
    returnPath: function (c) {
      var from = c.sender.from, rp = c.sender.returnPath;
      if (!from || !rp || !from.org || !rp.org || from.org === rp.org) { return []; }
      var h = c.headers.first('return-path');
      return [{ text: c.text.slice(h.valueStart, h.firstLineEnd), start: h.valueStart, end: h.firstLineEnd,
        detail: 'Bounce address is @' + rp.domain + '; visible sender is @' + from.domain }];
    },
    spfFail: function (c) { return authEvidence(c.auth.spf, ['fail', 'hardfail', 'permerror'], 'SPF result: '); },
    spfSoftfail: function (c) { return authEvidence(c.auth.spf, ['softfail'], 'SPF result: '); },
    dkimFail: function (c) { return authEvidence(c.auth.dkim, ['fail', 'permerror'], 'DKIM result: '); },
    dmarcFail: function (c) { return authEvidence(c.auth.dmarc, ['fail'], 'DMARC result: '); },

    urlIp: function (c) { return c.urls.filter(function (u) { return isIp(u.host); }).map(urlEvidence('Destination is the IP address ')); },
    urlShortener: function (c) {
      return c.urls.filter(function (u) { return R.SHORTENERS.indexOf(u.host.replace(/^www\./, '')) !== -1; })
        .map(urlEvidence('Shortened by '));
    },
    urlLookalike: function (c) {
      var out = [];
      c.urls.forEach(function (u) {
        if (isIp(u.host)) { return; }
        if (/(^|\.)xn--/.test(u.host)) {
          out.push({ text: u.raw, start: u.start, end: u.end, detail: '"' + u.host + '" uses punycode (xn--), which can display as look-alike letters' });
          return;
        }
        var hit = brandInHost(u.host);
        if (hit && !ownedBy(u.host, hit.brand)) {
          out.push({ text: u.raw, start: u.start, end: u.end,
            detail: '"' + u.host + '" ' + (hit.confusable ? 'imitates' : 'uses the name') + ' ' + hit.brand.name + ', but the registered domain is ' + u.org });
        }
      });
      return out;
    },
    urlSuspicious: function (c) {
      var out = [];
      c.urls.forEach(function (u) {
        var reasons = suspiciousReasons(u);
        if (reasons.length) { out.push({ text: u.raw, start: u.start, end: u.end, detail: u.host + ': ' + reasons.join('; ') }); }
      });
      return out;
    },
    misleadingLink: function (c) { return c.misleading; },

    executableAttachment: function (c) {
      return c.attachments.filter(function (a) { return a.executable; })
        .map(function (a) { return { text: a.name, start: a.start, end: a.end, detail: a.name + ' — ' + a.executable }; });
    },
    unusualAttachment: function (c) {
      var out = [];
      c.attachments.forEach(function (a) {
        if (a.unusual.length) { out.push({ text: a.name, start: a.start, end: a.end, detail: a.name + ' — ' + a.unusual.join('; ') }); }
      });
      if (/‮/.test(c.text) && !out.length) {
        var i = c.text.indexOf('‮');
        out.push({ text: '‮', start: i, end: i + 1, detail: 'Hidden right-to-left override character found — used to disguise file names' });
      }
      return out;
    }
  };

  function authEvidence(result, bad, label) {
    if (!result || bad.indexOf(result.result) === -1) { return []; }
    return [{ text: result.text, start: result.start, end: result.end, detail: label + result.result }];
  }

  function urlEvidence(prefix) {
    return function (u) { return { text: u.raw, start: u.start, end: u.end, detail: prefix + u.host }; };
  }

  /* ------------------------------------------------------------------ */
  /* Phrase rules                                                        */
  /* ------------------------------------------------------------------ */

  function phraseEvidence(rule, masked, text) {
    if (rule.unless && rule.unless.some(function (p) { return p.test(masked); })) { return []; }
    var out = [];
    var seen = {};
    rule.patterns.forEach(function (p) {
      var re = new RegExp(p.source, p.flags.indexOf('i') !== -1 ? 'gi' : 'g');
      var m;
      while ((m = re.exec(masked)) !== null) {
        if (!m[0]) { re.lastIndex++; continue; }
        var key = m[0].toLowerCase().replace(/\s+/g, ' ');
        var overlaps = out.some(function (e) { return m.index < e.end && m.index + m[0].length > e.start; });
        if (!seen[key] && !overlaps) {
          seen[key] = true;
          out.push({ text: text.slice(m.index, m.index + m[0].length), start: m.index, end: m.index + m[0].length });
        }
      }
    });
    out.sort(function (a, b) { return a.start - b.start; });
    return out;
  }

  /* ------------------------------------------------------------------ */
  /* Recommendations                                                     */
  /* ------------------------------------------------------------------ */

  var BASE_ADVICE = {
    high: [
      'Don\'t click any links, open attachments or reply to this message.',
      'Report it: use your email app\'s "Report phishing" option, or forward it to your IT/security team if it reached a work account. Then delete it.'
    ],
    suspicious: [
      'Treat this message with caution until you have verified it.',
      'Contact the sender using details you already trust — their official website, app, or a phone number you have used before — not anything in this email.'
    ],
    low: [
      'No strong warning signs were found, but that does not prove the email is safe. Attackers can write convincing messages that pass these checks.',
      'Still verify anything involving money, passwords, codes or urgent requests through an official channel.'
    ]
  };

  /* ------------------------------------------------------------------ */
  /* Main entry point                                                    */
  /* ------------------------------------------------------------------ */

  function analyse(input) {
    var text = String(input == null ? '' : input).replace(/\r\n?/g, '\n');
    var truncated = false;
    if (text.length > MAX_INPUT) { text = text.slice(0, MAX_INPUT); truncated = true; }

    var headers = extractHeaders(text);
    /* Links inside technical headers (e.g. server IPs in Authentication-Results) aren't links you could click. */
    var urls = extractUrls(text).filter(function (u) {
      return !headers.noisyRanges.some(function (r) { return u.start >= r.start && u.end <= r.end; });
    });
    var emailRanges = [];
    var emailRe = /[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi;
    var em;
    while ((em = emailRe.exec(text)) !== null) { emailRanges.push({ start: em.index, end: em.index + em[0].length }); }
    var masked = mask(text, urls.concat(emailRanges, headers.noisyRanges));

    var fromH = headers.first('from');
    var sender = {
      from: fromH ? parseAddress(fromH.value) : null,
      replyTo: headers.first('reply-to') ? parseAddress(headers.first('reply-to').value) : null,
      returnPath: headers.first('return-path') ? parseAddress(headers.first('return-path').value) : null
    };
    var auth = readAuth(headers, text);

    var ctx = {
      text: text, masked: masked, headers: headers, sender: sender, auth: auth, urls: urls,
      misleading: misleadingLinks(text), attachments: extractAttachments(masked, text)
    };

    var findings = [];
    R.RULES.forEach(function (rule) {
      var evidence = rule.type === 'phrases' ? phraseEvidence(rule, masked, text) : CHECKS[rule.check](ctx);
      if (evidence && evidence.length) {
        findings.push({
          id: rule.id, title: rule.title, group: rule.group, points: rule.weight, severity: severityFor(rule.weight),
          why: rule.why, advice: rule.advice,
          evidence: evidence.slice(0, MAX_EVIDENCE_PER_RULE), moreEvidence: Math.max(0, evidence.length - MAX_EVIDENCE_PER_RULE),
          allRanges: evidence.map(function (e) { return { start: e.start, end: e.end }; })
        });
      }
    });
    findings.sort(function (a, b) { return b.points - a.points; });
    findings.forEach(function (f, i) { f.ref = i + 1; });

    var rawTotal = findings.reduce(function (sum, f) { return sum + f.points; }, 0);
    var score = Math.min(100, rawTotal);
    var level = levelFor(score);

    var recommendations = BASE_ADVICE[level.key].slice();
    findings.forEach(function (f) { if (recommendations.indexOf(f.advice) === -1) { recommendations.push(f.advice); } });

    var marks = [];
    findings.forEach(function (f) {
      f.allRanges.forEach(function (r) { marks.push({ start: r.start, end: r.end, ref: f.ref, severity: f.severity, title: f.title }); });
    });

    var headersFound = !!(sender.from || sender.replyTo || sender.returnPath || auth.spf || auth.dkim || auth.dmarc);

    return {
      text: text,
      truncated: truncated,
      score: score,
      rawTotal: rawTotal,
      level: level,
      findings: findings,
      marks: marks,
      recommendations: recommendations,
      headersFound: headersFound,
      sender: sender,
      auth: {
        spf: auth.spf ? auth.spf.result : null,
        dkim: auth.dkim ? auth.dkim.result : null,
        dmarc: auth.dmarc ? auth.dmarc.result : null
      },
      links: urls.map(function (u) {
        var flags = [];
        if (isIp(u.host)) { flags.push('IP address'); }
        if (R.SHORTENERS.indexOf(u.host.replace(/^www\./, '')) !== -1) { flags.push('Shortened'); }
        var hit = !isIp(u.host) && brandInHost(u.host);
        if ((hit && !ownedBy(u.host, hit.brand)) || /(^|\.)xn--/.test(u.host)) { flags.push('Look-alike'); }
        if (suspiciousReasons(u).length) { flags.push('Odd structure'); }
        return { url: u.raw, host: u.host, registered: u.org, flags: flags };
      }),
      attachments: ctx.attachments.map(function (a) {
        return { name: a.name, ext: a.ext, flagged: !!(a.executable || a.unusual.length) };
      })
    };
  }

  var api = { analyse: analyse, orgDomain: orgDomain, levelFor: levelFor, severityFor: severityFor, rules: R };
  root.PEA = api;
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
})(typeof globalThis !== 'undefined' ? globalThis : this);
