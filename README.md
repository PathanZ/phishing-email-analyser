# Phishing Email Analyser

A free, private, educational tool that checks a pasted email for common phishing and social-engineering warning signs, then explains every one.

Paste a suspicious email and click **Analyse email**. You get:

- a risk score from 0 to 100,
- a band: **Low Risk** (0–24), **Suspicious** (25–59) or **High Risk** (60–100),
- the exact text behind each warning sign, highlighted in the email,
- the points each sign added and why it matters,
- practical next steps.

> This is an educational triage tool. It identifies warning signs. It **cannot** prove whether an email is safe or malicious.
> Never click a suspicious link or open an attachment just to test it, and verify important messages through the organisation's official website, app or known contact details.

## Privacy

Everything runs inside the visitor's browser tab:

- **Nothing leaves the device.** No email content is uploaded to a server, an AI service, an analytics provider or an API.
- **No tracking at all.** There are no cookies, no tracking, no analytics and no accounts, and nothing is saved.
- **Nothing loads from other websites.** No fonts, scripts or images come from third parties; the page uses system fonts.
- **The browser itself enforces this.** A Content Security Policy in `index.html` (`connect-src 'none'`) blocks the page from making any network request.
- **Pasted text is never run.** It is always displayed as plain text, so code hidden in a malicious email can't execute (protection against XSS).

## What it checks

| Group | Warning signs |
|---|---|
| Pressure and fear | Urgency language, threats of suspension or closure |
| Requests for secrets | Password requests, MFA/verification-code requests, "verify your account" sign-in lures |
| Money | Payment, gift-card and crypto requests; bank-detail changes; invoice language |
| Who it claims to be | Brand or department impersonation, generic greetings, secrecy or "boss is unavailable" pressure |
| Sender and authentication | Display-name spoofing, Reply-To and Return-Path mismatches, SPF, DKIM and DMARC failures (when headers are pasted) |
| Links | Raw IP addresses, URL shorteners, brand look-alike domains, suspicious structure, misleading link text |
| Attachments | Executable and script files, double extensions, macro-enabled documents, disk images, HTML/SVG attachments, password-protected archives, requests to enable macros |

Each sign adds a fixed number of points, **once**, however many times it appears. The total is capped at 100. The full table is shown on the site under "How the score works", generated directly from the rules file so it is always accurate.

## Gmail checker (optional)

The same rules can watch your **personal Gmail** automatically. `gmail/PhishCheck.gs` is a Google Apps Script that runs inside your own Google account:

- **Checks new emails automatically.** Every 5 minutes it checks new inbox emails using exactly the same rules and scores as the website.
- **Labels risky emails.** It adds the label `Phish Check/High Risk` or `Phish Check/Suspicious`; low-risk emails are left alone.
- **Never deletes anything.** It never deletes email or marks it as spam. Moving High Risk emails out of the inbox is an optional setting, off by default.
- **Sends you a short alert** when something scores High Risk. The alert lists the reasons but deliberately leaves out the suspicious email's links, addresses and file names, so nothing dangerous can be clicked from it.
- **Keeps your email in your Google account.** Nothing is sent to any other service.

Use it on a personal account only; work accounts usually need IT approval for scripts.

### Install

1. **Copy the script.** Open [`gmail/PhishCheck.gs`](gmail/PhishCheck.gs) on GitHub and click the **Copy raw file** button (two overlapping squares, top right of the file).
2. **Create a project.** Go to [script.google.com](https://script.google.com), signed in to the Gmail account you want to protect, and click **New project**.
3. **Paste the code.** Select everything in the editor (`Ctrl+A`), delete it, then paste. Click the project name ("Untitled project") and rename it **Phish Check**.
4. **Save.** Click the disk icon.
5. **Run setup.** In the toolbar's function menu, choose **setup**, then click **Run**.
6. **Approve the permissions.**
   - Click **Review permissions** and choose your account.
   - Google will say **"Google hasn't verified this app"**. That is expected for any script you write yourself. Click **Advanced → Go to Phish Check (unsafe)**.
   - The permission list includes reading, sending and deleting email. Google asks for this for every script that uses Gmail; this script only reads, labels and sends you alerts. You can confirm that by reading the code, which is exactly the habit to have before granting any app access.
   - Click **Allow**.
7. **Check it's running.** The log at the bottom shows the first check. From now on it runs every 5 minutes by itself.

**Changing settings:** edit the `CONFIG` section at the top of the script, save, then run `setup` again.
**Stopping it:** choose **uninstall** and click **Run**. Labels already added are kept.
**Trying the demos without touching your inbox:** run `testWithDemoEmails` and read the log.

### What to expect

- **Some marketing emails will be flagged.** They use urgency and tracking links, so some will land in *Suspicious*. That is the rules working as designed, not a fault. Adjust weights in `js/rules.js` if it's too noisy.
- **Labels can arrive up to 5 minutes late.** An email may sit unlabelled for a few minutes, so it's a second opinion, not a gate before delivery.
- **Google limits how much a free script can run each day.** At one check every 5 minutes, this stays well inside the limits.

## Project layout

```
index.html          The page
css/styles.css      The look (light and dark themes, mobile layout)
js/rules.js         Every warning sign: points, explanation, advice, phrases. Edit this to tune the analyser.
js/analyser.js      The engine that applies the rules. Works in browsers, Node.js and Google Apps Script.
js/samples.js       Six fictional demo emails (reserved example domains only)
js/app.js           Connects the page to the engine and draws the results
gmail/PhishCheck.gs The Gmail checker: one file to paste into Google Apps Script (generated)
gmail/src/          Its source: settings, and the Gmail-specific code
tools/build-gmail.js  Rebuilds gmail/PhishCheck.gs from the rules + engine + Gmail code
tests/run-tests.js  Automated checks for the analyser
tests/gmail-mock-test.js  Tests the Gmail checker against a pretend inbox
favicon.svg         Site icon
```

## Changing the rules

Open `js/rules.js`.

- **To change how much a sign counts,** edit its `weight`.
- **To make a rule recognise a new phrase,** add a pattern to its `patterns` list.

Then rebuild the Gmail script and run the checks to make sure nothing broke:

```
node tools/build-gmail.js
node tests/run-tests.js
node tests/gmail-mock-test.js
```

## Running the checks

With [Node.js](https://nodejs.org) installed, run from this folder:

```
node tests/run-tests.js
```

The checks confirm that:

- each demo email lands in its expected band,
- every rule can fire,
- common innocent text isn't flagged,
- the score never exceeds 100.

## Hosting

This is a fully static site with no build step, no server and no dependencies. It can be hosted free on GitHub Pages:

1. In the repository on GitHub, go to **Settings → Pages**.
2. Under **Build and deployment**, choose **Deploy from a branch**.
3. Pick the `main` branch and the `/ (root)` folder, then **Save**.

The site appears at `https://<username>.github.io/<repository-name>/` within a minute or two.

## Demo emails

All six demo emails are fictional. Every domain uses names reserved for documentation (`.example`, `.test`) and every IP address is in a reserved documentation range (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`), so none of them can lead anywhere real.

## Limitations

- **Plain-text copies lose link destinations.** Copying an email as plain text usually loses the real destination behind link text like "Click here". Paste the "Show original" or "View source" version to detect misleading links.
- **It never checks anything online.** It doesn't visit links, open attachments or look anything up in reputation databases.
- **Authentication results can be faked in pasted text.** SPF, DKIM and DMARC results are only trustworthy when they come from your own mail provider's headers.
- **A careful attacker can avoid every rule here.** Treat a low score as "no obvious signs", not "safe".
