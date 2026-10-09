/*
 * ====================================================================
 *  Phishing Email Analyser — Gmail checker (Google Apps Script)
 * ====================================================================
 *  Runs inside YOUR Google account. Every few minutes it looks at new
 *  emails in your inbox, runs the same warning-sign rules as the
 *  website, and adds a Gmail label:
 *
 *      Phish Check/High Risk      Phish Check/Suspicious
 *
 *  It NEVER deletes email and never marks anything as spam.
 *  Email content is never sent anywhere outside your Google account.
 *
 *  Setup (once):
 *    1. Paste this whole file into a new project at script.google.com
 *    2. Choose the "setup" function at the top and click Run
 *    3. Approve the permissions Google asks for
 *  To stop it: choose "uninstall" and click Run.
 * ====================================================================
 */

/* -------------------- Your settings (safe to change) -------------------- */

var CONFIG = {
  // How often to check, in minutes. Google allows 1, 5, 10, 15 or 30.
  CHECK_EVERY_MINUTES: 5,

  // Label names. A "/" makes a nested label in Gmail's sidebar.
  LABEL_HIGH: 'Phish Check/High Risk',
  LABEL_SUSPICIOUS: 'Phish Check/Suspicious',

  // Label Suspicious emails too? (High Risk is always labelled.)
  LABEL_SUSPICIOUS_EMAILS: true,

  // Move High Risk emails out of the inbox? They stay findable under the
  // label and in "All Mail". Nothing is ever deleted. Off by default.
  MOVE_HIGH_RISK_OUT_OF_INBOX: false,

  // Email yourself a short alert when a High Risk email arrives.
  SEND_ALERT_FOR_HIGH_RISK: true,

  // Also alert for Suspicious emails? (Can be noisy with marketing mail.)
  SEND_ALERT_FOR_SUSPICIOUS: false,

  // Subject prefix of alert emails. The checker skips its own alerts.
  ALERT_SUBJECT_PREFIX: '[Phish Check]',

  // When first installed, also check emails from this many hours ago.
  FIRST_RUN_LOOKBACK_HOURS: 24,

  // Safety limits so one run never takes too long.
  MAX_EMAILS_PER_RUN: 40,
  MAX_SECONDS_PER_RUN: 240
};

/* --------------------------------------------------------------------------
   Below: the warning-sign rules and the analysis engine (identical to the
   website's), then the Gmail-specific code. You don't need to edit them.
   -------------------------------------------------------------------------- */

/* ---------- from js/rules.js ---------- */
/*
 * Phishing Email Analyser — rule definitions
 * -------------------------------------------
 * This file is the "knowledge" of the analyser. It contains no logic you
 * need to understand to change it: each rule has a title, a fixed number of
 * points, a plain-English explanation and a piece of advice.
 *
 * To change how much a warning sign counts, edit its `weight`.
 * To teach a phrase rule a new phrase, add a pattern to its `patterns` list.
 *
 * Patterns are "regular expressions" — a compact way of describing text.
 *   \b      = a word boundary (so "urgent" doesn't match inside "insurgent")
 *   (a|b)   = either a or b
 *   ?       = the thing before is optional
 *   [^.\n]{0,40} = up to 40 characters that are not a full stop or new line
 *                  (keeps matches inside one sentence)
 * Patterns ending in /i ignore upper/lower case.
 *
 * This file works unchanged in a web browser, in Node.js (for the automated
 * tests) and in Google Apps Script (for the future Gmail version).
 */
(function (root) {
  'use strict';

  /* Score bands. A score at or above a number moves into that band. */
  var THRESHOLDS = { suspicious: 25, high: 60 };

  /*
   * Well-known brands that phishing emails pretend to be, and the domains
   * those brands genuinely send from or link to. If an email *claims* to be
   * one of these but points somewhere else, that is a warning sign.
   * Short tokens (3–4 letters) must match a whole word of the domain.
   */
  var BRANDS = [
    { name: 'Microsoft', tokens: ['microsoft', 'office365', 'microsoft365', 'outlook', 'onedrive', 'sharepoint', 'msonline'],
      domains: ['microsoft.com', 'office.com', 'office365.com', 'live.com', 'outlook.com', 'microsoftonline.com', 'sharepoint.com', 'onedrive.com', 'azure.com', 'windows.net', 'microsoft365.com'] },
    { name: 'PayPal', tokens: ['paypal'], domains: ['paypal.com', 'paypal.ca', 'paypal.me'] },
    { name: 'Apple', tokens: ['apple', 'icloud', 'appleid'], domains: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', tokens: ['amazon'], domains: ['amazon.com', 'amazon.ca', 'amazon.co.uk', 'amazonaws.com'] },
    { name: 'Netflix', tokens: ['netflix'], domains: ['netflix.com'] },
    { name: 'Google', tokens: ['google', 'gmail'], domains: ['google.com', 'google.ca', 'gmail.com', 'googleusercontent.com'] },
    { name: 'DocuSign', tokens: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Dropbox', tokens: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'Canada Post', tokens: ['canadapost', 'postescanada'], domains: ['canadapost.ca', 'canadapost-postescanada.ca', 'postescanada.ca'] },
    { name: 'Purolator', tokens: ['purolator'], domains: ['purolator.com'] },
    { name: 'FedEx', tokens: ['fedex'], domains: ['fedex.com'] },
    { name: 'DHL', tokens: ['dhl'], domains: ['dhl.com', 'dhl.ca'] },
    { name: 'UPS', tokens: ['ups'], domains: ['ups.com'] },
    { name: 'Interac', tokens: ['interac', 'etransfer'], domains: ['interac.ca'] },
    { name: 'Canada Revenue Agency', tokens: ['cra', 'craarc'], domains: ['canada.ca', 'cra-arc.gc.ca'] }
  ];

  /* Link-shortening services. They hide where a link really goes. */
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 't.ly', 'lnkd.in', 'bl.ink', 'short.io', 'v.gd',
    'qrco.de', 'shorte.st', 'adf.ly', 'tr.im', 'x.co', 'soo.gd', 'clck.ru'
  ];

  /* Email-marketing click-tracking services. Newsletters route links through
     these, so "link text shows one site but goes to another" is normal for
     them and is not reported as misleading. (Attackers sometimes abuse these
     services too — the other link checks still apply.) */
  var CLICK_TRACKERS = [
    'list-manage.com', 'mailchimp.com', 'mcusercontent.com', 'sendgrid.net', 'mandrillapp.com', 'mailgun.org',
    'sparkpostmail.com', 'exacttarget.com', 'hubspotlinks.com', 'hs-sites.com', 'hubspotemail.net', 'rs6.net',
    'klaviyomail.com', 'klclick.com', 'klclick1.com', 'awstrack.me', 'mailjet.com', 'cmail19.com', 'cmail20.com',
    'createsend.com', 'sailthru.com', 'braze.com', 'customeriomail.com', 'mktossl.com', 'mkt.com', 'substack.com',
    'eventbrite.com', 'urldefense.com', 'safelinks.protection.outlook.com'
  ];

  /* Top-level domains that are cheap and disproportionately used for abuse,
     or that look like file names (.zip, .mov). Legitimate sites exist on all
     of them, so this only ever adds to a "suspicious link" finding. */
  var RISKY_TLDS = ['zip', 'mov', 'top', 'xyz', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga',
    'work', 'rest', 'cam', 'icu', 'buzz', 'cyou', 'sbs', 'quest', 'monster', 'bond', 'lol'];

  /* Words that phishing sites put in their domain names to look official. */
  var LURE_WORDS = ['login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security',
    'account', 'update', 'webscr', 'auth', 'wallet', 'unlock', 'support', 'billing', 'confirm', 'recovery'];

  /* Attachment types, grouped by why they matter. */
  var ATTACHMENT_TYPES = {
    executable: ['exe', 'scr', 'bat', 'cmd', 'pif', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'msi',
      'msix', 'ps1', 'psm1', 'lnk', 'jar', 'apk', 'dll', 'cpl', 'reg', 'appx', 'appinstaller', 'gadget', 'url', 'chm'],
    diskImage: ['iso', 'img', 'vhd', 'vhdx'],
    macro: ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'xlsb', 'pptm', 'potm', 'ppam', 'sldm'],
    webPage: ['html', 'htm', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml'],
    archive: ['zip', 'rar', '7z', 'ace', 'cab', 'gz', 'tgz', 'arj', 'xz'],
    document: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'csv', 'rtf', 'odt']
  };

  /*
   * The rules.
   *   type 'phrases' — looks for any of the `patterns` in the email text.
   *                    `unless` patterns switch the rule off if found.
   *   type 'check'   — a structural test (links, headers, attachments)
   *                    carried out by analyser.js; the `check` names it.
   * Each rule adds its weight ONCE, however many times it matches, so
   * repeating a phrase cannot inflate the score.
   * Weights of 25+ mean "this sign alone is enough to be Suspicious":
   * direct requests for secrets or money changes, executables, macros, and
   * links that are provably deceptive (raw IPs, brand look-alikes, link text
   * that lies about its destination).
   */
  var RULES = [
    /* ---------- Pressure and fear ---------- */
    {
      id: 'urgency', group: 'Pressure and fear', title: 'Urgency or pressure language', weight: 10, type: 'phrases',
      why: 'Scammers rush you so you act before you think or check. Real organisations rarely demand action within minutes or hours.',
      advice: 'Slow down. A genuine deadline can be confirmed by contacting the organisation through its official website or app.',
      patterns: [
        /\burgent(ly)?\b/i, /\bimmediate(ly)?\b/i, /\bact (now|fast|quickly)\b/i,
        /\bwithin (the next )?(\d+|one|two|twelve|twenty[- ]four|forty[- ]eight|seventy[- ]two) ?(hours?|hrs?|minutes?|mins?)\b/i,
        /\b(final|last) (notice|warning|reminder|chance|attempt)\b/i, /\bexpires? (today|tonight|soon|shortly|in \d+)\b/i,
        /\btime[- ]sensitive\b/i, /\bright away\b/i, /\bas soon as possible\b/i, /\basap\b/i,
        /\bfailure to (respond|comply|verify|act|update|confirm|pay)\b/i, /\b(by|before) (the )?(end|close) of (the )?(day|business)\b/i,
        /\b(today|now) only\b/i, /\bdo(n't| not) delay\b/i
      ]
    },
    {
      id: 'account_threat', group: 'Pressure and fear', title: 'Threat of account suspension or loss', weight: 15, type: 'phrases',
      why: 'Threatening to lock, close or delete your account creates fear, which pushes people into clicking without checking.',
      advice: 'Check your account status by opening the official app or typing the website address yourself — never through the email\'s link.',
      patterns: [
        /\b(account|mailbox|e-?mail|access|service|card|profile|subscription|membership)\b[^.\n]{0,40}\b(suspended|deactivated|disabled|closed|terminated|locked|restricted|blocked|deleted|frozen|on hold)\b/i,
        /\b(suspension|deactivation|termination|closure|restriction) of your\b/i,
        /\blose (access|all (of )?(your )?(data|files|e-?mails|messages))\b/i,
        /\bpermanently (deleted|removed|closed|disabled|lost)\b/i,
        /\b(unusual|suspicious|unauthori[sz]ed|unrecogni[sz]ed) (sign[- ]?in|log[- ]?in|activity|access|transaction|payment)s?\b/i
      ]
    },

    /* ---------- Requests for secrets ---------- */
    {
      id: 'password_request', group: 'Requests for secrets', title: 'Asks for your password', weight: 25, type: 'phrases',
      why: 'Legitimate organisations never ask you to send, confirm or "verify" your password by email. This is one of the strongest phishing signs.',
      advice: 'Never type or send your password because an email asked. If you already did, change it immediately from the official site and turn on multi-factor authentication.',
      patterns: [
        /\b(confirm|verify|enter|provide|update|re-?enter|validate|submit|send|reply with|type|share)\b[^.\n]{0,40}\b(current |existing |old )?password\b/i,
        /\bpassword\b[^.\n]{0,25}\b(below|in (the|your) reply|to (us|this address))\b/i,
        /\b(username|user ?id|e-?mail( address)?) and password\b/i
      ]
    },
    {
      id: 'mfa_request', group: 'Requests for secrets', title: 'Asks for a verification (MFA) code', weight: 25, type: 'phrases',
      why: 'One-time codes exist to stop someone who has your password. Anyone asking you to share or read back a code is almost certainly trying to log in as you.',
      advice: 'Never share a verification code with anyone, including people claiming to be support staff. Deny any sign-in prompt you did not start.',
      patterns: [
        /\b(send|share|forward|provide|reply with|read (it )?(out|back)|tell|give|text)\b[^.\n]{0,40}\b(verification|security|authentication|one[- ]time|2fa|mfa|otp|login|log-in|access|confirmation|6[- ]digit|six[- ]digit) ?(code|pin|passcode|number)s?\b/i,
        /\b(code|pin)\b[^.\n]{0,30}\b(we (just )?sent|you (just )?received|sent to your (phone|mobile|device))\b[^.\n]{0,40}\b(reply|send|share|provide|forward|confirm)\b/i,
        /\bapprove (the |this |our )?(sign[- ]?in|log[- ]?in|authentication|mfa|push|security) (request|prompt|notification)\b/i
      ],
      /* Genuine code emails usually say "never share this code" — if so, don't flag. */
      unless: [/\b(never|do not|don't|dont)\s+(share|give|send|forward|tell)\b/i]
    },
    {
      id: 'credential_harvest', group: 'Requests for secrets', title: 'Pushes you to sign in or "verify" your account', weight: 20, type: 'phrases',
      why: 'The classic phishing trick: send you to a fake sign-in page that looks real, then capture what you type. "Verify", "restore" and "mailbox full" are common lures.',
      advice: 'If you think something needs attention, open the service the way you normally do (app or bookmark) and check there.',
      patterns: [
        /\b(verify|confirm|validate|update|re-?activate|restore|unlock|secure|authenticate|reconfirm|re-?validate)\s+(your|the)\s+(account|identity|mailbox|e-?mail account|credentials|login|log-in|sign-in|profile|billing( information| details)?|payment (details|information|method))\b/i,
        /\b(log|sign)[- ]?(in|on)\b[^.\n]{0,45}\bto (verify|confirm|restore|unlock|avoid|keep|continue using|reactivate|retain|prevent|secure)\b/i,
        /\bclick\b[^.\n]{0,25}\b(link|button|here|below)\b[^.\n]{0,30}\b(verify|confirm|log ?in|sign ?in|restore|unlock|validate|reactivate|retain|keep)\b/i,
        /\b(mailbox|storage|inbox|e-?mail) (is |has )?(full|almost full|over (its |the )?(quota|limit)|reached (its |the )?(limit|quota|capacity))\b/i,
        /\b\d*\s*(pending|held|undelivered) (incoming )?(messages|e-?mails)\b/i,
        /\b(password|account) (will )?(expire|expires|expiring)\b/i
      ]
    },

    /* ---------- Money ---------- */
    {
      id: 'payment_request', group: 'Money', title: 'Requests payment, gift cards or crypto', weight: 20, type: 'phrases',
      why: 'Gift cards, wire transfers and cryptocurrency are hard to trace and nearly impossible to reverse — that is exactly why scammers ask for them. Small "delivery" or "customs" fees are a common lure.',
      advice: 'No real organisation asks to be paid in gift cards. Confirm any payment request by phone using a number you already know — not one in the email.',
      patterns: [
        /\bgift ?cards?\b/i, /\b(itunes|apple|google play|steam|amazon|ebay|walmart|best buy|prepaid) (gift )?cards?\b/i,
        /\bscratch (off )?the back\b/i, /\bwire (the )?(transfer|funds|payment|money)\b/i, /\bwire transfer\b/i,
        /\b(send|transfer|pay)\b[^.\n]{0,30}\b(bitcoin|btc|crypto(currency)?|usdt|ethereum)\b/i,
        /\b(bitcoin|crypto) (wallet|address|atm)\b/i, /\bmake (a |the )?(urgent |immediate |quick )?payment\b/i,
        /\bprocess (a |the |this )?(payment|transfer|wire)\b/i,
        /\bpay (a|the) (small |customs |delivery |re-?delivery |release |processing |shipping )?(fee|charge|duty|balance)\b/i,
        /\b(customs|re-?delivery|delivery|shipping|release|processing|handling) (fee|charge)\b/i
      ]
    },
    {
      id: 'bank_change', group: 'Money', title: 'Asks to change bank or payment details', weight: 25, type: 'phrases',
      why: 'Business email compromise (BEC) attacks pose as a supplier or executive and ask you to send money to a "new" account. Losses are often large and unrecoverable.',
      advice: 'Never change payment details based on an email. Call the supplier or colleague on a phone number you already have on file to confirm.',
      patterns: [
        /\b(new|updated|update|change[ds]?|changing|different|alternate|alternative)\b[^.\n]{0,30}\b(bank(ing)?|account|payment|remittance|wire|deposit|payroll)\s+(details|info(rmation)?|account|instructions)\b/i,
        /\b(iban|swift code|routing number|transit number|institution number|sort code)\b/i,
        /\b(our|my) (bank|account|banking details) (has |have )?changed\b/i,
        /\bdirect deposit\b[^.\n]{0,40}\b(change|update|new)\b/i
      ]
    },
    {
      id: 'invoice', group: 'Money', title: 'Invoice or payment-due language', weight: 8, type: 'phrases',
      why: 'Fake invoices rely on you paying or opening an attachment out of habit. This is only a concern if you were not expecting an invoice from this sender.',
      advice: 'If you weren\'t expecting this invoice, check it against your own records or contact the company directly before paying or opening anything.',
      patterns: [
        /\binvoice\b/i, /\b(overdue|outstanding|unpaid) (invoice|balance|payment|amount)\b/i,
        /\bpayment (is )?(due|overdue|pending|past due)\b/i, /\bremittance\b/i, /\bpurchase order\b/i,
        /\bstatement of account\b/i, /\bpro-?forma\b/i
      ]
    },

    /* ---------- Who it claims to be ---------- */
    {
      id: 'impersonation', group: 'Who it claims to be', title: 'Claims to be a well-known brand or department', weight: 10, type: 'phrases',
      why: 'Phishing borrows trusted names — Microsoft, a bank, a courier, "the IT department" — so you lower your guard. A big name in the email proves nothing about who sent it.',
      advice: 'Compare the sender\'s actual address and any link destinations with the organisation\'s real domain.',
      patterns: [
        /\b(microsoft|office ?365|microsoft 365|outlook|onedrive|sharepoint|paypal|apple|icloud|amazon|netflix|google|docusign|dropbox|canada post|purolator|fedex|dhl|interac|canada revenue agency|bank)\b[^.\n]{0,15}\b(team|support|security|billing|notifications?|account (team|department|services)|help ?desk|alerts?|delivery services)\b/i,
        /\bIT (department|team|support|help ?desk|service ?desk|security)\b/,
        /\b(technical|security|help ?desk|service ?desk|system|e-?mail|mail|network) (administrator|admin|department|team)\b/i,
        /\bwebmaster\b/i
      ]
    },
    {
      id: 'generic_greeting', group: 'Who it claims to be', title: 'Generic greeting instead of your name', weight: 5, type: 'phrases',
      why: 'Mass phishing is sent to thousands of people, so it often can\'t greet you by name. On its own this is weak evidence; combined with other signs it matters.',
      advice: 'Organisations you have an account with usually know your name. Treat a generic greeting as a reason to look more closely.',
      patterns: [
        /\bdear (valued |esteemed )?(customer|user|client|member|account ?holder|sir\/madam|sir or madam|beneficiary|recipient|e-?mail user|subscriber|colleague)s?\b/i,
        /\bdear [a-z0-9._%+-]+@[a-z0-9.-]+\b/i,
        /\bhello (customer|user|member|client)\b/i
      ]
    },
    {
      id: 'secrecy', group: 'Who it claims to be', title: 'Secrecy or bypassing normal checks', weight: 12, type: 'phrases',
      why: 'Executive-impersonation scams ask you to keep things quiet and claim the "boss" can\'t be reached — so you can\'t verify the request.',
      advice: 'Any request to skip normal approval or keep a payment secret is a reason to verify in person or by phone.',
      patterns: [
        /\bkeep (this|it) (confidential|between us|private|quiet|to yourself)\b/i,
        /\b(don't|do not|please don't) (tell|discuss|mention)\b/i,
        /\b(i'?m|i am) (currently )?(in a meeting|in meetings|travell?ing|on a flight|unavailable|tied up)\b/i,
        /\bcan(not|'t) (talk|take (any )?calls?|be reached)\b/i,
        /\bare you (available|at your desk|around)\b/i,
        /\b(quick|small|urgent|discreet) (favou?r|task|errand)\b/i
      ]
    },

    /* ---------- Sender and authentication (needs pasted headers) ---------- */
    {
      id: 'display_name_spoof', group: 'Sender and authentication', title: 'Sender name doesn\'t match sender address', weight: 15, type: 'check', check: 'displayName',
      why: 'Anyone can type any display name. "Microsoft Account Team" sending from an unrelated domain is a classic disguise — most phones only show the name.',
      advice: 'Always expand the sender to see the full address, and check its domain belongs to the organisation.'
    },
    {
      id: 'reply_to_mismatch', group: 'Sender and authentication', title: 'Replies go to a different domain', weight: 15, type: 'check', check: 'replyTo',
      why: 'The Reply-To header controls where your reply actually goes. When it differs from the sender\'s domain, a scammer can impersonate someone while collecting the replies elsewhere.',
      advice: 'Before replying, check which address your reply will be sent to. If it is unexpected, start a fresh email to a known address instead.'
    },
    {
      id: 'return_path_mismatch', group: 'Sender and authentication', title: 'Bounce address uses a different domain', weight: 5, type: 'check', check: 'returnPath',
      why: 'The Return-Path is the technical "envelope" sender. Mailing services legitimately use their own, so this is weak evidence — but it can expose a spoofed From address.',
      advice: 'Treat this as supporting evidence only; look at it together with SPF, DKIM and DMARC.'
    },
    {
      id: 'spf_fail', group: 'Sender and authentication', title: 'SPF check failed', weight: 15, type: 'check', check: 'spfFail',
      why: 'SPF lets a domain list which servers may send its mail. A failure means the message came from a server the domain did not authorise.',
      advice: 'A failed SPF check on an email asking for anything sensitive is a strong reason not to trust it.'
    },
    {
      id: 'spf_softfail', group: 'Sender and authentication', title: 'SPF soft-fail', weight: 6, type: 'check', check: 'spfSoftfail',
      why: 'A soft-fail means the sending server probably isn\'t authorised, but the domain owner asked receivers to be lenient. Weaker than a full failure.',
      advice: 'Combine this with the other signs; on its own it can be a misconfiguration.'
    },
    {
      id: 'dkim_fail', group: 'Sender and authentication', title: 'DKIM signature failed', weight: 12, type: 'check', check: 'dkimFail',
      why: 'DKIM is a digital signature added by the sending domain. A failure means the signature is invalid — the message may have been forged or altered.',
      advice: 'Don\'t act on requests in a message whose signature fails without verifying them another way.'
    },
    {
      id: 'dmarc_fail', group: 'Sender and authentication', title: 'DMARC check failed', weight: 20, type: 'check', check: 'dmarcFail',
      why: 'DMARC ties SPF and DKIM to the visible From address. A failure means the email could not prove it really came from the domain it displays — a strong spoofing sign.',
      advice: 'Treat the sender as unverified. Report the message to your email provider or IT/security team.'
    },

    /* ---------- Links ---------- */
    {
      id: 'url_ip', group: 'Links', title: 'Link points to a raw IP address', weight: 25, type: 'check', check: 'urlIp',
      why: 'Real organisations link to their domain name, not to a bare number like 192.0.2.10. IP-address links are used to avoid domain-based blocking and to hide who runs the site.',
      advice: 'Don\'t open the link. If you need the service, go to its website by typing the address you know.'
    },
    {
      id: 'url_shortener', group: 'Links', title: 'Shortened link hides the destination', weight: 12, type: 'check', check: 'urlShortener',
      why: 'Link shorteners disguise where you\'ll end up. Legitimate companies sometimes use them, but in an unexpected email they hide a destination you can\'t inspect.',
      advice: 'Don\'t click shortened links in unexpected emails. Some shorteners offer a "preview" feature, but the safest choice is to go to the organisation directly.'
    },
    {
      id: 'url_lookalike', group: 'Links', title: 'Link imitates a known brand\'s domain', weight: 25, type: 'check', check: 'urlLookalike',
      why: 'Scammers register domains containing a brand name (e.g. "microsoft-login-verify.example") or swap similar-looking characters. Only the part just before the final ".com" — the registered domain — shows who owns a site.',
      advice: 'Read domains from right to left. If the registered domain isn\'t the organisation\'s real one, it isn\'t them.'
    },
    {
      id: 'url_suspicious', group: 'Links', title: 'Link has suspicious structure', weight: 10, type: 'check', check: 'urlSuspicious',
      why: 'Some link patterns are rarely used by legitimate senders: an "@" that hides the real host, many hyphens or sub-domains, unencrypted http://, abuse-prone domain endings, or official-sounding words like "secure-login" bolted onto an unrelated domain.',
      advice: 'Hover over (or long-press) links to see their real destination before trusting them — but don\'t open them to "test" them.'
    },
    {
      id: 'misleading_link', group: 'Links', title: 'Link text doesn\'t match where it goes', weight: 25, type: 'check', check: 'misleadingLink',
      why: 'An email can show one address as the link text while the link actually goes somewhere else. This can only be detected when the pasted text includes the real destination (HTML source, or text like "Click here <https://…>").',
      advice: 'On a computer, hover over a link to reveal its true destination. On a phone, long-press it — and never tap just to find out.'
    },

    /* ---------- Attachments ---------- */
    {
      id: 'executable_attachment', group: 'Attachments', title: 'Mentions an executable or script file', weight: 30, type: 'check', check: 'executableAttachment',
      why: 'Files ending in .exe, .js, .vbs, .lnk, .hta and similar run code on your computer the moment they are opened. Ordinary emails almost never need to send them.',
      advice: 'Do not open it. Delete the message, or report it to your IT/security team if this is a work account.'
    },
    {
      id: 'unusual_attachment', group: 'Attachments', title: 'Unusual or disguised attachment', weight: 15, type: 'check', check: 'unusualAttachment',
      why: 'Disguises include double extensions ("invoice.pdf.exe"), hidden reversed text, macro-enabled Office files, disk images (.iso, .img), web-page attachments (.html, .svg) that open fake login forms, and password-protected archives that slip past scanners.',
      advice: 'Don\'t open unexpected attachments. If you were expecting a file, confirm with the sender through a different channel first.'
    },
    {
      id: 'macro_request', group: 'Attachments', title: 'Asks you to enable macros or editing', weight: 25, type: 'phrases',
      why: 'Macros are small programs inside Office documents. Asking you to click "Enable Content" or "Enable Editing" is how malicious documents switch off Office\'s built-in protection.',
      advice: 'Never enable macros or content in a document that arrived by email unless your IT team has confirmed it is safe.',
      patterns: [
        /\benable (editing|content|macros?|active ?x)\b/i,
        /\b(click|press|select)\s+["'“]?enable\b/i,
        /\bmacros?\b[^.\n]{0,30}\b(enable|allow|turn on|activate)\b/i,
        /\bprotected view\b/i
      ]
    }
  ];

  var api = {
    THRESHOLDS: THRESHOLDS,
    BRANDS: BRANDS,
    SHORTENERS: SHORTENERS,
    CLICK_TRACKERS: CLICK_TRACKERS,
    RISKY_TLDS: RISKY_TLDS,
    LURE_WORDS: LURE_WORDS,
    ATTACHMENT_TYPES: ATTACHMENT_TYPES,
    RULES: RULES
  };

  root.PEA_RULES = api;
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
})(typeof globalThis !== 'undefined' ? globalThis : this);

/* ---------- from js/analyser.js ---------- */
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

  function isTracker(host) {
    var list = R.CLICK_TRACKERS || [];
    return list.some(function (d) { return host === d || host.slice(-(d.length + 1)) === '.' + d; });
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
      if (isTracker(target.host)) { return; }
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
      if (brand && target.host && !ownedBy(target.host, brand) && !isTracker(target.host)) {
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

/* ---------- from js/samples.js ---------- */
/*
 * Phishing Email Analyser — demonstration emails
 * -----------------------------------------------
 * Every email here is FICTIONAL. All people, companies and banks are made up.
 * Every domain uses names reserved for documentation and testing, so none
 * of them can ever be a real website:
 *   *.example  *.test  example.com      (reserved by RFC 2606 / RFC 6761)
 *   192.0.2.x  198.51.100.x  203.0.113.x  (reserved "documentation" IPs, RFC 5737)
 * Real brand names (e.g. Microsoft) appear only as the thing being imitated.
 *
 * `expected` is the result the automated tests check for.
 */
(function (root) {
  'use strict';

  var SAMPLES = [
    {
      id: 'obvious',
      label: 'Obvious phishing',
      expected: ['high'],
      text: [
        'From: Cedarline Bank Security <alerts@cedarline-secure-verify.example>',
        'Reply-To: recovery.desk@freemail.example',
        'Subject: URGENT: Your account has been suspended',
        '',
        'Dear Valued Customer,',
        '',
        'We detected unusual sign-in activity on your Cedarline Bank account. Your account has been suspended for your protection.',
        '',
        'To restore your access you must verify your account within 24 hours. Failure to verify will result in your account being permanently closed.',
        '',
        'Click the link below and confirm your username and password:',
        'http://192.0.2.47/cedarline/login.php',
        '',
        'You will receive a 6-digit security code on your phone. Please reply with the verification code so our team can complete the process.',
        '',
        'Download and complete the attached form: Account_Recovery_Form.pdf.exe',
        '',
        'Cedarline Bank Security Team'
      ].join('\n')
    },
    {
      id: 'sophisticated',
      label: 'Sophisticated phishing',
      expected: ['suspicious', 'high'],
      text: [
        'From: Priya Sandhu via FileDrop <notifications@filedrop-share.example>',
        'To: alex.chen@northwind.example',
        'Subject: Priya Sandhu shared "FY27 Compensation Review.xlsx" with you',
        'Authentication-Results: mx.northwind.example; spf=pass smtp.mailfrom=filedrop-share.example; dkim=pass header.d=filedrop-share.example; dmarc=pass header.from=filedrop-share.example',
        '',
        'Hi Alex,',
        '',
        'Priya Sandhu (priya.sandhu@northwind.example) has shared a file with you.',
        '',
        '    FY27 Compensation Review.xlsx',
        '    "Hi Alex - before Thursday\'s leadership meeting, could you look over the proposed adjustments for your team? Please keep this confidential until the announcement."',
        '',
        'Open document <https://northwind-sharepoint.files-portal.example/s/8Kq2/FY27-review>',
        '',
        'This link will expire in 48 hours. You may be asked to sign in with your Microsoft 365 account to confirm access.',
        '',
        'FileDrop - file sharing for teams'
      ].join('\n')
    },
    {
      id: 'm365',
      label: 'Fake Microsoft 365 warning',
      expected: ['high'],
      text: [
        'From: Microsoft 365 Account Team <no-reply@m365-mailbox-alerts.example>',
        'Reply-To: support@o365-helpcentre.example',
        'Return-Path: <bounce@bulk-sender.example>',
        'Subject: Action required: your mailbox storage is full',
        'Authentication-Results: mx.inbound.example;',
        '       spf=fail (sender IP is 203.0.113.25) smtp.mailfrom=m365-mailbox-alerts.example;',
        '       dkim=none (message not signed);',
        '       dmarc=fail action=quarantine header.from=m365-mailbox-alerts.example',
        '',
        'Microsoft 365',
        '',
        'Your mailbox is almost full (99.6% of 50 GB used).',
        '',
        'You have 37 pending incoming messages that could not be delivered. To avoid losing access, sign in to verify your account and upgrade your storage at no cost.',
        '',
        'Verify now <https://microsoft365-account.verify-storage.example/owa/auth>',
        '',
        'If you do not verify within 12 hours your mailbox will be disabled and all messages will be permanently deleted.',
        '',
        'Microsoft 365 Security Team'
      ].join('\n')
    },
    {
      id: 'parcel',
      label: 'Fake parcel delivery',
      expected: ['high'],
      text: [
        'From: Northline Parcel <delivery@northline-parcel-tracking.example>',
        'Subject: Delivery attempt failed - package NP-48210-CA on hold',
        '',
        'Hello Customer,',
        '',
        'We attempted to deliver your package today but no one was available to sign for it. Your parcel is now being held at our depot.',
        '',
        'To schedule redelivery, a redelivery fee of $1.99 must be paid within 48 hours, or the package will be returned to sender.',
        '',
        'Confirm your payment details and choose a new delivery date:',
        'http://northline-delivery-secure-pay.example/redeliver?id=NP48210',
        '',
        'Tracking number: NP-48210-CA',
        'Northline Parcel'
      ].join('\n')
    },
    {
      id: 'bec',
      label: 'Fake invoice / BEC',
      expected: ['high'],
      text: [
        'From: Daniel Okafor <daniel.okafor@northwind-traders.example>',
        'Reply-To: daniel.okafor.ceo@freemail.example',
        'To: accounts@northwind.example',
        'Subject: Re: Supplier payment - Harbourline Logistics',
        'Authentication-Results: mx.northwind.example; spf=softfail smtp.mailfrom=northwind-traders.example; dkim=none; dmarc=fail header.from=northwind-traders.example',
        '',
        'Hi Sam,',
        '',
        'Are you at your desk? I need a quick favour handled today.',
        '',
        'Harbourline Logistics have sent through their overdue invoice #HL-2291 ($48,750.00). Their bank has changed after an audit, so please use the updated banking details in the attached letter rather than the ones on file:',
        '',
        '    Updated_Banking_Details_Harbourline.pdf',
        '',
        'Please process the wire transfer before end of day - they have threatened to pause our shipments. I\'m in meetings all afternoon and can\'t take calls, so just reply by email once it\'s done. Keep this between us until I\'ve briefed the board.',
        '',
        'Thanks,',
        'Daniel',
        'CEO, Northwind Traders'
      ].join('\n')
    },
    {
      id: 'legit',
      label: 'Legitimate email',
      expected: ['low'],
      text: [
        'From: Riverbend Public Library <notices@riverbendlibrary.example>',
        'To: alex.chen@mail.example',
        'Subject: Your hold is ready for pickup',
        'Authentication-Results: mx.mail.example; spf=pass smtp.mailfrom=riverbendlibrary.example; dkim=pass header.d=riverbendlibrary.example; dmarc=pass header.from=riverbendlibrary.example',
        '',
        'Hi Alex,',
        '',
        'Good news - the item you placed on hold is ready to collect at the Riverbend Central branch:',
        '',
        '    The Quiet Harbour (paperback)',
        '    Pick up by Saturday, 18 October',
        '',
        'You can see all your holds and loans by signing in to your library account at https://riverbendlibrary.example/account or in the Riverbend Library app.',
        '',
        'Branch hours are Monday to Saturday, 9 a.m. to 8 p.m.',
        '',
        'Happy reading,',
        'Riverbend Public Library',
        'We will never ask for your password or PIN by email.'
      ].join('\n')
    }
  ];

  root.PEA_SAMPLES = SAMPLES;
  if (typeof module !== 'undefined' && module.exports) { module.exports = SAMPLES; }
})(typeof globalThis !== 'undefined' ? globalThis : this);

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
