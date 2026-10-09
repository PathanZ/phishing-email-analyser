/*
 * Phishing Email Analyser — interface
 * ------------------------------------
 * Connects the page to the analysis engine and draws the results.
 *
 * Security note: everything from the pasted email is inserted as plain TEXT
 * (createTextNode / textContent), never as HTML. A malicious email can contain
 * hidden code; treating it as text means that code is displayed, not run.
 */
(function () {
  'use strict';

  var PEA = window.PEA;
  var SAMPLES = window.PEA_SAMPLES || [];
  var RULES = PEA.rules.RULES;
  var T = PEA.rules.THRESHOLDS;

  var input = document.getElementById('email-input');
  var analyseBtn = document.getElementById('analyse-btn');
  var clearBtn = document.getElementById('clear-btn');
  var charCount = document.getElementById('char-count');
  var errorBox = document.getElementById('input-error');
  var results = document.getElementById('results');
  var resultsBody = document.getElementById('results-body');
  var headersToggle = document.getElementById('headers-toggle');
  var headersHelp = document.getElementById('headers-help');

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* Build an element. Children may be strings (always added as text) or nodes. */
  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] === null || attrs[k] === undefined || attrs[k] === false) { return; }
        if (k === 'className') { node.className = attrs[k]; }
        else if (k === 'text') { node.textContent = attrs[k]; }
        else { node.setAttribute(k, attrs[k] === true ? '' : attrs[k]); }
      });
    }
    (children || []).forEach(function (c) {
      if (c === null || c === undefined || c === false) { return; }
      node.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    });
    return node;
  }

  /* ---------------- Input area ---------------- */

  function updateCount() {
    var n = input.value.length;
    charCount.textContent = n.toLocaleString() + (n === 1 ? ' character' : ' characters');
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = !msg;
  }

  var chips = document.getElementById('sample-chips');
  SAMPLES.forEach(function (s) {
    var b = el('button', { type: 'button', className: 'chip', 'data-sample': s.id }, [s.label]);
    b.addEventListener('click', function () {
      input.value = s.text;
      updateCount();
      run();
    });
    chips.appendChild(b);
  });

  input.addEventListener('input', function () { updateCount(); if (input.value.trim()) { showError(''); } });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); }
  });
  analyseBtn.addEventListener('click', run);
  clearBtn.addEventListener('click', function () {
    input.value = '';
    updateCount();
    showError('');
    results.hidden = true;
    resultsBody.textContent = '';
    input.focus();
  });
  headersToggle.addEventListener('click', function () {
    var open = headersToggle.getAttribute('aria-expanded') === 'true';
    headersToggle.setAttribute('aria-expanded', String(!open));
    headersHelp.hidden = open;
  });

  /* ---------------- Run ---------------- */

  function run() {
    if (!input.value.trim()) {
      showError('Paste an email into the box first, or try one of the fictional demos.');
      input.focus();
      return;
    }
    showError('');
    var result = PEA.analyse(input.value);
    render(result);
    results.hidden = false;
    results.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    results.focus({ preventScroll: true });
  }

  /* ---------------- Results ---------------- */

  var SUMMARY = {
    high: 'Several strong warning signs. Treat this as a likely phishing attempt until proven otherwise.',
    suspicious: 'Some warning signs. Be cautious and verify the message before doing anything it asks.',
    low: 'Few or no warning signs from this checklist. That does not prove the email is safe.'
  };

  function render(r) {
    resultsBody.textContent = '';
    resultsBody.appendChild(renderVerdict(r));

    var notes = [];
    if (!r.headersFound) {
      notes.push('No email headers were found, so the sender, Reply-To and SPF/DKIM/DMARC checks were skipped. Paste the full “original” or “source” view for a more complete check.');
    }
    if (r.text.trim().length < 60) { notes.push('This is a very short piece of text, so the result is limited.'); }
    if (r.truncated) { notes.push('The email was very long, so only the first 200,000 characters were analysed.'); }
    if (notes.length) {
      resultsBody.appendChild(el('div', { className: 'notice' }, notes.map(function (n) { return el('p', null, [n]); })));
    }

    var grid = el('div', { className: 'results-grid' }, [renderLedger(r), renderSpecimen(r)]);
    resultsBody.appendChild(grid);

    var lower = el('div', { className: 'results-grid results-grid-lower' }, [renderNextSteps(r), renderFacts(r)]);
    resultsBody.appendChild(lower);
  }

  function renderVerdict(r) {
    var count = r.findings.length;
    var marker = el('div', { className: 'meter-marker' }, [el('span', { className: 'meter-marker-value' }, [String(r.score)])]);
    var meter = el('div', { className: 'meter', role: 'img', 'aria-label': 'Score ' + r.score + ' out of 100, in the ' + r.level.label + ' band' }, [
      el('div', { className: 'meter-track' }, [
        el('div', { className: 'meter-band meter-low' }),
        el('div', { className: 'meter-band meter-suspicious' }),
        el('div', { className: 'meter-band meter-high' })
      ]),
      marker,
      el('div', { className: 'meter-scale', 'aria-hidden': 'true' }, [
        el('span', { className: 'tick tick-0' }, ['0']),
        el('span', { className: 'tick tick-s' }, [String(T.suspicious)]),
        el('span', { className: 'tick tick-h' }, [String(T.high)]),
        el('span', { className: 'tick tick-100' }, ['100'])
      ])
    ]);

    // Size the bands from the thresholds so they always match rules.js.
    var bands = meter.querySelectorAll('.meter-band');
    bands[0].style.flexBasis = T.suspicious + '%';
    bands[1].style.flexBasis = (T.high - T.suspicious) + '%';
    bands[2].style.flexBasis = (100 - T.high) + '%';
    meter.querySelector('.tick-s').style.left = T.suspicious + '%';
    meter.querySelector('.tick-h').style.left = T.high + '%';

    marker.style.left = reduceMotion ? r.score + '%' : '0%';
    if (!reduceMotion) {
      requestAnimationFrame(function () { requestAnimationFrame(function () { marker.style.left = r.score + '%'; }); });
    }

    var signs = count === 0 ? 'No warning signs found' : count + (count === 1 ? ' warning sign found' : ' warning signs found');
    var capped = r.rawTotal > 100 ? ' The signs add up to ' + r.rawTotal + ' points; the score is capped at 100.' : '';

    return el('div', { className: 'verdict verdict-' + r.level.key }, [
      el('div', { className: 'verdict-top' }, [
        el('div', { className: 'verdict-score' }, [
          el('span', { className: 'score-number' }, [String(r.score)]),
          el('span', { className: 'score-out-of' }, ['/ 100'])
        ]),
        el('div', { className: 'verdict-words' }, [
          el('p', { className: 'verdict-label' }, [el('span', { className: 'verdict-icon', 'aria-hidden': 'true' }), r.level.label]),
          el('p', { className: 'verdict-summary' }, [SUMMARY[r.level.key]]),
          el('p', { className: 'verdict-meta' }, [signs + '.' + capped])
        ])
      ]),
      meter,
      el('p', { className: 'verdict-disclaimer' }, ['This score estimates risk from warning signs. It is not proof that the email is malicious or safe.'])
    ]);
  }

  function renderLedger(r) {
    var wrap = el('section', { className: 'card ledger-card', 'aria-labelledby': 'ledger-title' }, [
      el('h3', { id: 'ledger-title' }, ['Why it scored ' + r.score])
    ]);
    if (!r.findings.length) {
      wrap.appendChild(el('p', { className: 'empty' }, ['None of the ' + RULES.length + ' warning signs in this tool’s checklist were found. Stay cautious with anything involving money, passwords or urgency.']));
      return wrap;
    }
    var list = el('ol', { className: 'ledger' });
    r.findings.forEach(function (f) {
      var evidence = el('ul', { className: 'evidence' }, f.evidence.map(function (e) {
        return el('li', null, e.detail ? [e.detail] : [el('q', null, [e.text.replace(/\s+/g, ' ').trim()])]);
      }));
      if (f.moreEvidence) { evidence.appendChild(el('li', { className: 'more' }, ['and ' + f.moreEvidence + ' more'])); }
      var item = el('li', { className: 'ledger-item sev-' + f.severity, id: 'finding-' + f.ref, tabindex: '-1' }, [
        el('div', { className: 'ledger-row' }, [
          el('span', { className: 'ref', 'aria-hidden': 'true' }, [String(f.ref)]),
          el('span', { className: 'ledger-title' }, [f.title]),
          el('span', { className: 'points' }, ['+' + f.points, el('span', { className: 'visually-hidden' }, [' points'])])
        ]),
        evidence,
        el('details', { className: 'why' }, [
          el('summary', null, ['Why this matters']),
          el('p', null, [f.why])
        ])
      ]);
      list.appendChild(item);
    });
    wrap.appendChild(list);
    wrap.appendChild(el('p', { className: 'ledger-total' }, [
      el('span', null, ['Total']),
      el('span', null, [r.rawTotal > 100 ? r.rawTotal + ' points, capped at 100' : r.rawTotal + ' points'])
    ]));
    return wrap;
  }

  /* The pasted email, with each warning sign highlighted where it occurs. */
  function renderSpecimen(r) {
    var text = r.text;
    var rank = { low: 1, medium: 2, high: 3 };
    var owner = new Int32Array(text.length).fill(-1);
    r.marks.forEach(function (m, idx) {
      for (var i = m.start; i < m.end && i < text.length; i++) {
        var cur = owner[i];
        if (cur === -1 || rank[m.severity] > rank[r.marks[cur].severity]) { owner[i] = idx; }
      }
    });

    var pre = el('pre', { className: 'specimen', tabindex: '0', 'aria-label': 'The email you pasted, with warning signs highlighted' });
    var i = 0;
    var lastRef = null;
    while (i < text.length) {
      var o = owner[i];
      var j = i + 1;
      while (j < text.length && owner[j] === o) { j++; }
      var chunk = text.slice(i, j);
      if (o === -1) {
        pre.appendChild(document.createTextNode(chunk));
        lastRef = null;
      } else {
        var m = r.marks[o];
        var mark = el('mark', { className: 'hl hl-' + m.severity, 'data-ref': String(m.ref), title: m.ref + '. ' + m.title });
        if (lastRef !== m.ref) { mark.appendChild(el('span', { className: 'hl-ref', 'aria-hidden': 'true' }, [String(m.ref)])); }
        mark.appendChild(document.createTextNode(chunk));
        pre.appendChild(mark);
        lastRef = m.ref;
      }
      i = j;
    }
    pre.addEventListener('click', function (e) {
      var mark = e.target.closest ? e.target.closest('mark[data-ref]') : null;
      if (!mark) { return; }
      var target = document.getElementById('finding-' + mark.getAttribute('data-ref'));
      if (target) {
        target.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
        target.focus({ preventScroll: true });
        target.classList.remove('flash');
        void target.offsetWidth;
        target.classList.add('flash');
      }
    });

    return el('section', { className: 'card specimen-card', 'aria-labelledby': 'specimen-title' }, [
      el('div', { className: 'card-head' }, [
        el('h3', { id: 'specimen-title' }, [r.marks.length ? 'Where the signs appear' : 'The email you pasted']),
        r.marks.length ? el('div', { className: 'legend', 'aria-hidden': 'true' }, [
          el('span', { className: 'legend-item' }, [el('span', { className: 'swatch hl-high' }), 'Strong']),
          el('span', { className: 'legend-item' }, [el('span', { className: 'swatch hl-medium' }), 'Moderate']),
          el('span', { className: 'legend-item' }, [el('span', { className: 'swatch hl-low' }), 'Weak'])
        ]) : null
      ]),
      r.marks.length ? el('p', { className: 'card-note' }, ['Numbers match the list of warning signs. Select a highlight to jump to its explanation.']) : null,
      pre
    ]);
  }

  function renderNextSteps(r) {
    return el('section', { className: 'card steps-card', 'aria-labelledby': 'steps-title' }, [
      el('h3', { id: 'steps-title' }, ['What to do next']),
      el('ul', { className: 'steps' }, r.recommendations.map(function (t) { return el('li', null, [t]); }))
    ]);
  }

  function authChip(name, value) {
    var state, words;
    if (!value) { state = 'missing'; words = 'not found'; }
    else if (value === 'pass') { state = 'pass'; words = 'pass'; }
    else if (value === 'fail' || value === 'permerror' || value === 'hardfail') { state = 'fail'; words = value; }
    else if (value === 'softfail') { state = 'warn'; words = 'softfail'; }
    else { state = 'neutral'; words = value; }
    return el('li', { className: 'auth auth-' + state }, [el('span', { className: 'auth-name' }, [name]), el('span', { className: 'auth-result' }, [words])]);
  }

  function addressRow(label, a) {
    if (!a || !a.address) { return null; }
    return el('div', { className: 'fact-row' }, [
      el('dt', null, [label]),
      el('dd', null, [a.name ? a.name + ' ' : '', el('code', null, ['<' + a.address + '>'])])
    ]);
  }

  function renderFacts(r) {
    var card = el('section', { className: 'card facts-card', 'aria-labelledby': 'facts-title' }, [
      el('h3', { id: 'facts-title' }, ['What was found in the email'])
    ]);

    // Sender
    var dl = el('dl', { className: 'facts' }, [
      addressRow('From', r.sender.from),
      addressRow('Reply-To', r.sender.replyTo),
      addressRow('Return-Path', r.sender.returnPath)
    ]);
    card.appendChild(el('h4', null, ['Sender']));
    card.appendChild(dl.children.length ? dl : el('p', { className: 'muted' }, ['No sender headers found.']));

    // Authentication
    card.appendChild(el('h4', null, ['Authentication']));
    card.appendChild(el('ul', { className: 'auth-list' }, [authChip('SPF', r.auth.spf), authChip('DKIM', r.auth.dkim), authChip('DMARC', r.auth.dmarc)]));
    card.appendChild(el('p', { className: 'small muted' }, ['A pass only proves which domain sent the email — scammers can pass these checks with domains they own.']));

    // Links (shown as inert text, never clickable)
    card.appendChild(el('h4', null, ['Links (' + r.links.length + ')']));
    if (!r.links.length) {
      card.appendChild(el('p', { className: 'muted' }, ['No links found.']));
    } else {
      var ul = el('ul', { className: 'link-list' });
      r.links.slice(0, 25).forEach(function (l) {
        ul.appendChild(el('li', null, [
          el('code', { className: 'link-url' }, [l.url]),
          el('span', { className: 'link-meta' }, [
            'Registered domain: ', el('strong', null, [l.registered])
          ].concat(l.flags.map(function (f) { return el('span', { className: 'flag' }, [f]); })))
        ]));
      });
      card.appendChild(ul);
      if (r.links.length > 25) { card.appendChild(el('p', { className: 'small muted' }, ['and ' + (r.links.length - 25) + ' more'])); }
    }

    // Attachments
    if (r.attachments.length) {
      card.appendChild(el('h4', null, ['File names mentioned (' + r.attachments.length + ')']));
      card.appendChild(el('ul', { className: 'file-list' }, r.attachments.map(function (a) {
        return el('li', null, [el('code', null, [a.name]), a.flagged ? el('span', { className: 'flag' }, ['Risky type']) : null]);
      })));
    }
    return card;
  }

  /* ---------------- "How the score works" table, built from rules.js ---------------- */

  function renderRulesTable() {
    var host = document.getElementById('rules-table');
    var groups = [];
    RULES.forEach(function (rule) { if (groups.indexOf(rule.group) === -1) { groups.push(rule.group); } });
    groups.forEach(function (g) {
      var rows = RULES.filter(function (rule) { return rule.group === g; });
      var table = el('table', { className: 'rules' }, [
        el('caption', null, [g]),
        el('thead', null, [el('tr', null, [
          el('th', { scope: 'col' }, ['Warning sign']),
          el('th', { scope: 'col', className: 'num' }, ['Points']),
          el('th', { scope: 'col' }, ['Why it matters'])
        ])]),
        el('tbody', null, rows.map(function (rule) {
          return el('tr', { className: 'sev-' + PEA.severityFor(rule.weight) }, [
            el('th', { scope: 'row' }, [rule.title]),
            el('td', { className: 'num' }, ['+' + rule.weight]),
            el('td', null, [rule.why])
          ]);
        }))
      ]);
      host.appendChild(el('div', { className: 'table-wrap' }, [table]));
    });
  }

  renderRulesTable();
  updateCount();
})();
