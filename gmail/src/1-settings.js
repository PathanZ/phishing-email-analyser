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
