/**
 * Synthetic Email Test Fixtures for PhishScope
 * Standardized test cases labeled clearly as SYNTHETIC for development,
 * CI/CD testing, and analyst workflow demonstrations.
 */

export interface SyntheticFixture {
  id: string;
  name: string;
  category: 'legitimate' | 'credential_phishing' | 'routing_anomaly' | 'punycode_spoof' | 'malformed_partial' | 'executable_attachment';
  description: string;
  expectedLabel: string;
  rawContent: string;
}

export const SYNTHETIC_FIXTURES: SyntheticFixture[] = [
  {
    id: 'fixture-01-legitimate',
    name: 'Legitimate Corporate Engineering Digest',
    category: 'legitimate',
    description: 'Clean enterprise email with valid SPF pass, valid DKIM pass, strict DMARC alignment, and corporate domain links.',
    expectedLabel: 'likely_legitimate',
    rawContent: `Received: from mail-relay-02.acme-corp.com (mail-relay-02.acme-corp.com [198.51.100.25])
    by mx.destination.org with ESMTPS id abc123xyz
    for <analyst@destination.org>; Tue, 03 Nov 2026 14:15:20 +0000
Received: from mail-internal.acme-corp.com (mail-internal.acme-corp.com [10.0.4.15])
    by mail-relay-02.acme-corp.com with ESMTP id def456uvw;
    Tue, 03 Nov 2026 14:15:15 +0000
Authentication-Results: mx.destination.org;
    dkim=pass (signature was verified) header.d=acme-corp.com header.s=corp2026;
    spf=pass (mx.destination.org: domain of newsletter@acme-corp.com designates 198.51.100.25 as permitted sender) smtp.mailfrom=newsletter@acme-corp.com;
    dmarc=pass (p=reject sp=reject dis=none) header.from=acme-corp.com
Received-SPF: pass (mx.destination.org: domain of newsletter@acme-corp.com designates 198.51.100.25 as permitted sender) client-ip=198.51.100.25;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=acme-corp.com; s=corp2026;
    t=1793715315; bh=7/gZ9rPqfK...;
    h=From:To:Subject:Date:Message-ID;
    b=d8aBcDeFgHiJkLmNoPqRsTuVwXyZ...
From: "Acme Corp Tech Digest" <newsletter@acme-corp.com>
To: "Security Team" <analyst@destination.org>
Reply-To: "Acme Support" <support@acme-corp.com>
Return-Path: <newsletter@acme-corp.com>
Subject: Engineering Architecture Updates - Q4 2026
Date: Tue, 03 Nov 2026 14:15:00 +0000
Message-ID: <digest-20261103-9942@acme-corp.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <h2>Engineering Architecture Updates - Q4 2026</h2>
  <p>Here is our scheduled quarterly infrastructure update summary.</p>
  <p>All core systems continue operating smoothly within designated parameters.</p>
  <p>Review the full documentation on our knowledge base at 
     <a href="https://acme-corp.com/docs/q4-report">https://acme-corp.com/docs/q4-report</a>.
  </p>
  <p>Regards,<br>Acme Engineering Operations</p>
</body>
</html>`
  },
  {
    id: 'fixture-02-credential-phish',
    name: 'High-Risk Banking Credential Harvesting Phish',
    category: 'credential_phishing',
    description: 'Impersonates PayPal with display name spoofing, SPF hard failure, Anchor Text vs Href divergence, and urgent coercive language.',
    expectedLabel: 'likely_phishing',
    rawContent: `Received: from mail.attacker-server.xyz (mail.attacker-server.xyz [185.220.101.5])
    by mx.destination.org with ESMTP id phish7788
    for <analyst@destination.org>; Tue, 03 Nov 2026 16:30:10 +0000
Authentication-Results: mx.destination.org;
    dkim=fail (bad signature) header.d=attacker-server.xyz;
    spf=fail (mx.destination.org: domain of service@paypal.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=service@paypal.com;
    dmarc=fail (p=reject) header.from=paypal.com
Received-SPF: fail (mx.destination.org: 185.220.101.5 is unauthorized) client-ip=185.220.101.5;
From: "PayPal Security Center <service@paypal.com>" <support-alert@attacker-server.xyz>
To: <analyst@destination.org>
Reply-To: <credentials-harvest@darkmail.ru>
Return-Path: <bounce@unregistered-host.net>
Subject: URGENT: Your PayPal account has been suspended within 24 hours
Date: Tue, 03 Nov 2026 16:30:00 +0000
Message-ID: <badmessage-88339@attacker-server.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
  <div style="font-family: Arial, sans-serif;">
    <h3 style="color: #c00;">URGENT SECURITY ALERT</h3>
    <p>Dear Customer,</p>
    <p>We detected unauthorized login attempts on your account. Your account access will be permanently suspended within 24 hours unless you re-authenticate immediately.</p>
    <p>
      Please confirm your identity and verify your password right now:
      <br><br>
      <!-- Critical phishing indicator: Display text says paypal.com, href points to rogue IP -->
      <a href="http://185.220.101.5/login-verification?token=steal883">https://www.paypal.com/security/verify-account</a>
    </p>
    <p>Failure to respond immediately will result in permanent closure of your assets.</p>
    <p>PayPal Trust and Safety</p>
  </div>
</body>
</html>`
  },
  {
    id: 'fixture-03-routing-anomaly',
    name: 'Forged Routing Chain & Negative Transit Time',
    category: 'routing_anomaly',
    description: 'Header injection simulation with negative time delta between hops (-3600s clock reversal), missing DKIM, and internal/public spoofing.',
    expectedLabel: 'potentially_suspicious',
    rawContent: `Received: from gateway.relay-node.com (gateway.relay-node.com [203.0.113.88])
    by mx.destination.org with ESMTP id hop2
    for <analyst@destination.org>; Tue, 03 Nov 2026 10:00:00 +0000
Received: from forged-internal.org (forged-internal.org [198.51.100.99])
    by gateway.relay-node.com with ESMTP id hop1;
    Tue, 03 Nov 2026 11:05:00 +0000
Authentication-Results: mx.destination.org;
    spf=softfail (mx.destination.org: transitioning domain of alert@sender-domain.com) smtp.mailfrom=alert@sender-domain.com;
    dmarc=none
From: "Billing Department" <alert@sender-domain.com>
To: "Accounts Payable" <analyst@destination.org>
Subject: Invoice #88392 Overdue Notification
Date: Tue, 03 Nov 2026 10:00:00 +0000
Message-ID: <inv-88392@sender-domain.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Please find the attached invoice documentation.
Ensure payment is settled prior to end of month.
Access the invoice portal at: http://203.0.113.88:8080/portal/view`
  },
  {
    id: 'fixture-04-punycode-homoglyph',
    name: 'Punycode IDN Homoglyph Spoof Attack',
    category: 'punycode_spoof',
    description: 'Uses an internationalized domain with Cyrillic lookalike letters (xn--pple-43d.com) to mimic Apple ID authentication.',
    expectedLabel: 'likely_phishing',
    rawContent: `Received: from mail.bulletproof-host.is (mail.bulletproof-host.is [198.18.0.42])
    by mx.destination.org with ESMTPS id idn1122
    for <analyst@destination.org>; Tue, 03 Nov 2026 09:12:00 +0000
Authentication-Results: mx.destination.org;
    spf=pass (mx.destination.org: domain of support@xn--pple-43d.com designates 198.18.0.42) smtp.mailfrom=support@xn--pple-43d.com;
    dkim=none;
    dmarc=fail (p=none) header.from=apple.com
From: "Apple Support" <support@apple.com>
Return-Path: <bounce@xn--pple-43d.com>
To: <analyst@destination.org>
Subject: Your Apple ID was used to sign in on a new device
Date: Tue, 03 Nov 2026 09:10:00 +0000
Message-ID: <apple-notice-99234@xn--pple-43d.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body>
  <p>Your Apple ID was recently accessed from a foreign browser in St. Petersburg, Russia.</p>
  <p>If this was not you, lock your credentials immediately at our identity portal:</p>
  <p><a href="https://xn--pple-43d.com/login/auth">https://appleid.apple.com/account/manage</a></p>
</body>
</html>`
  },
  {
    id: 'fixture-05-body-only-partial',
    name: 'Pasted Body Only (Missing Headers)',
    category: 'malformed_partial',
    description: 'Pasted body content lacking RFC 5322 headers. Tests graceful handling of missing routing and authentication evidence.',
    expectedLabel: 'insufficient_evidence',
    rawContent: `Hi team,

Can someone review the attached quarterly metrics when you have a moment?
Let me know if you need any adjustments before the partner briefing tomorrow.

Thanks,
Marcus`
  }
];
