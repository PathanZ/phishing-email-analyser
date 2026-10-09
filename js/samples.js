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
