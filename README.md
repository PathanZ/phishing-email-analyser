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

## Project layout

```
index.html          The page
css/styles.css      The look (light and dark themes, mobile layout)
js/rules.js         Every warning sign: points, explanation, advice, phrases. Edit this to tune the analyser.
js/analyser.js      The engine that applies the rules. Works in browsers, Node.js and Google Apps Script.
js/samples.js       Six fictional demo emails (reserved example domains only)
js/app.js           Connects the page to the engine and draws the results
tests/run-tests.js  Automated checks
favicon.svg         Site icon
```

## Changing the rules

Open `js/rules.js`.

- **To change how much a sign counts,** edit its `weight`.
- **To make a rule recognise a new phrase,** add a pattern to its `patterns` list.

Then run the checks to make sure nothing broke.

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
