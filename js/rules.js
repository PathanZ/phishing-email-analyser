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
