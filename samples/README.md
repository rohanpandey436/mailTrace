# Sample messages

Five complete RFC 822 messages (multipart text + HTML, three to four `Received`
hops, 2026 dates, the `Authentication-Results` a real receiving MTA would add).
Together they exercise every analyzer. Nothing here is live malware: the
"executable" is an inert `MZ` stub and the PDF is a one-line receipt.

**Before the demo** copy `deploy/.env.example` to `.env` at the project root (or
into `backend/`). It sets `MAILTRACE_ORG_DOMAINS=acme-corp.in` (the organisation
every sample targets) and
`MAILTRACE_EXECUTIVES=ceo,cfo,managing director,sarthak srivastava`. Without it
the lookalike check in sample 2 loses its strongest signal and that sample's
attribution and score both change - see the table.

**About the numbers below.** Every figure was measured on 2026-09-05 by running
each sample through `pipeline.analyze_bytes` with `enable_network=False`,
`org_domains=["acme-corp.in"]` and `sarthak srivastava` among the executives,
against a **clean, empty store**. Live enrichment can only raise these scores
(the Tor flag on sample 2's origin, for instance); it never lowers them. So can
re-uploading: a second copy of the same message shares `ip:`, `sender:` and
`domain:` indicators with the first, and the resulting `known_campaign_overlap`
finding lifts the network pillar - measured, sample 1 goes 83 to 87 and sample 2
goes 72 to 79. Delete the data directory before a demo if you want the table to
match.

| File | Category | Risk / severity | Attribution | Origin IP |
|---|---|---|---|---|
| `phishing_sbi_kyc.eml` | Phishing | 83, critical | `lookalike_domain` | 45.148.10.72 (hop 1, hosting) |
| `bec_payment_diversion.eml` | Fraud-Related | 72, high | `lookalike_domain` **only with `acme-corp.in` configured**; `undetermined` with stock defaults | 185.220.101.45 (hop 0, Tor exit range) |
| `legit_transactional.eml` | Legitimate | 4, low | `legitimate_sender` | 192.30.252.206 (hop 1, GitHub MTA, US) |
| `fraud_lottery_advance_fee.eml` | Fraud-Related | 60, high | `direct_attacker_infrastructure` | 197.210.85.12 (hop 0, MTN Nigeria) |
| `impersonation_ceo_gift_cards.eml` | Impersonated | 45, medium | `direct_attacker_infrastructure` | 49.36.220.14 (hop 0, Jio mobile, India) |

With the default `MAILTRACE_ALERT_THRESHOLD` of 70, samples 1 and 2 raise alerts
and the other three do not.

## phishing_sbi_kyc.eml

A State Bank of India KYC lure: display name "State Bank of India" on
`alerts@sbi-kyc-update.xyz`, Reply-To on Gmail
(`sbi.kyc.helpdesk@gmail.com`), `Authentication-Results` with `spf=fail`,
`dkim=none`, `dmarc=fail`, an `X-PHP-Originating-Script` header and
`X-Priority: 1 (Highest)` / `Importance: High`. The text demands KYC
re-verification "within 24 hours" under threat of suspension and a Rs. 999
penalty, and asks for account number, Aadhaar, PAN and OTP. The HTML button and
the "open this link" line both point to `http://sbi-online-kyc-verify.xyz/login`
while the visible anchor text reads `https://onlinesbi.sbi`; the button URL also
carries the recipient's address base64-encoded in the `uid` query parameter. The
chain runs localhost -> the attacker's own `srv-mail01.sbi-kyc-update.xyz`
(`45.148.10.72`, a hosting range) -> a `.icu` bulk-mail relay
(`193.42.33.118`) -> Google, with no TLS on the two attacker-side hops and a
`negative_delay` anomaly on the third.

Measured: **Phishing, risk 83, severity critical**, attribution
**`lookalike_domain`** at 0.80 - `sbi-kyc-update.xyz` is an `extra_token`
imitation of the `sbi` brand, so this one does not depend on your `.env`. The
`credential_harvesting` BEC pattern fires at 0.95, both `.xyz` links are rated
critical, and the rules and the classifier disagree (rules Phishing, model
Impersonated at p=0.52), so the verdict is reported at 0.70 confidence with a
`dual_validation_disagreement` finding. In the UI look at the spoofing badge row
(SPF, DMARC, Reply-To, display name all red), the Links & Files tab (anchor/href
mismatch, credential keywords, suspicious `.xyz` TLD), the Content tab (urgency
meter, credential terms, `credential_harvesting` BEC card) and the Trace tab map
with the origin marker on hop 1.

## bec_payment_diversion.eml

A business-email-compromise payment diversion aimed at `accounts@acme-corp.in`.
The sender "Rajesh Mehta, Director" writes from `rajesh.mehta@acme-corp-in.com`,
a registered lookalike of the protected `acme-corp.in`, with Reply-To on
Proton Mail; SPF, DKIM and DMARC are all `none`. The body asks Finance to
"update the beneficiary details for invoice #4471" (Rs. 18,45,000) with a new
account number and IFSC, "before 4 PM today", to "keep this confidential", to
handle it "over email only" and not to call the vendor on the old number. The
earliest hop is an authenticated submission (`ESMTPSA`) from
`185.220.101.45`, an address inside a well-known Tor exit block, and the `Date`
header is stamped +0100 although the persona claims to be an Indian director.

Measured **with `MAILTRACE_ORG_DOMAINS=acme-corp.in`**: **Fraud-Related, risk
72, severity high**, confidence 0.90, attribution **`lookalike_domain`** at
0.80. The `payment_diversion` pattern fires at confidence 1.00 (plus
`executive_impersonation` at 0.95 and `fake_invoice` at 0.50), and
`acme-corp-in.com` is flagged an `extra_token` imitation of `acme-corp.in`. At
72 this sample **is above** the default `MAILTRACE_ALERT_THRESHOLD` of 70, so it
raises an alert.

Measured **without** that setting (stock `MAILTRACE_ORG_DOMAINS=example.org`):
nothing knows `acme-corp.in` exists, the lookalike signal disappears, and the
sample lands at **risk 60** - the Fraud-Related floor, with a
`risk_floor_applied` finding - and attribution `undetermined` at 0.30. At 60 it
does not raise an alert. This is the single biggest reason to copy the `.env`
before demoing.

Live enrichment additionally raises the critical `tor_exit_node` finding on the
origin. In the UI look at the Content tab (payment-diversion evidence phrases,
secrecy and urgency cues), the Domains & Infra tab (`acme-corp-in.com` flagged
as a lookalike) and the recommended action to verify the bank change with the
vendor on a previously known phone number.

## legit_transactional.eml

The control sample: a GitHub payment receipt from `noreply@github.com` with
`spf=pass`, `dkim=pass` (`d=github.com`) and `dmarc=pass` under a `p=REJECT`
policy, Reply-To identical to From, and a Message-ID on the sender's domain.
Hop 0 is GitHub's internal worker on a private `10.48.115.21` address, hop 1 is
`out-27.smtp.github.com` (`192.30.252.206`, the origin, in the United States)
delivering over TLS (`ESMTPS`) to Google. The body mentions payment, a receipt
number and "Visa ending in 4402", links once to `github.com`, and attaches a
genuine PDF (`%PDF` magic bytes match the declared type; entropy 4.88
bits/byte).

Measured: **Legitimate, risk 4, severity low**, confidence 0.94, attribution
**`legitimate_sender`**. It demonstrates that financial vocabulary alone does
not trigger a fraud verdict and that the authentication badges, the
single-country geo trail and the clean attachment inventory all show green.

## fraud_lottery_advance_fee.eml

An advance-fee lottery scam: "Reserve Bank of India - RBI Prize Fund" on a
`yahoo.com` mailbox announces a Rs. 25,00,000 win, demands contact "within 72
hours", requests full name, Aadhaar, PAN, bank account and IFSC, and asks for a
"processing and insurance fee" of Rs. 4,850, adding a Nigerian (+234) WhatsApp
number and an instruction not to disclose the win. The subject is RFC 2047
base64-encoded UTF-8 (it contains the rupee sign), the mailer is
`PHPMailer 6.9.1`, and the attachment `claim_form.pdf.exe` is declared
`application/pdf` but starts with `MZ` executable bytes. SPF, DKIM and DMARC all
pass for `yahoo.com`, so authentication says nothing about the false identity.
Hop 0 is an authenticated Yahoo submission (`ESMTPA`, no TLS) from
`197.210.85.12` (MTN Nigeria, a residential mobile network) by a host calling
itself `DESKTOP-K8J2M1`.

Measured: **Fraud-Related, risk 60, severity high** - not critical - with
confidence 0.92 and attribution **`direct_attacker_infrastructure`** at 0.60 (a
throwaway free-mail box posing as RBI). 60 is exactly the Fraud-Related risk
floor and a `risk_floor_applied` finding says so; the deterministic score is
lower because the message carries no links at all, zeroing the 0.25-weighted URL
pillar. At 60 it sits below the default alert threshold of 70. The attachment
alone reads 7.90 bits/byte and is rated critical. In the UI look at the
attachment row (double extension, MIME mismatch, executable magic -> critical),
the origin geolocated to Nigeria against the "held in Mumbai" claim, the
`bulk_mailer` and `display_name_spoof` findings, and the reward, secrecy and
urgency cues.

## impersonation_ceo_gift_cards.eml

The first touch of an executive-impersonation thread (the gift-card request
follows once the victim replies). "Sarthak Srivastava (CEO)" writes from
`sarthak.ceo.office@gmail.com` to `priya.nair@acme-corp.in`: "Are you at your
desk? I need you to handle something urgent ... in a meeting with the board ...
can't take calls. Reply on this email only." There are no links and no
attachments, the plain-text body is 52 words, and Gmail's SPF, DKIM and DMARC
all pass. Hop 0 is an `ESMTPSA` submission from `49.36.220.14` (Reliance Jio
mobile network, India) through `smtp.gmail.com`.

Measured: **Impersonated, risk 45, severity medium**, confidence 0.96, via the
`executive_impersonation` pattern at 1.00 and the display-name check (the name
matches a configured executive and the `CEO` title while the domain is not
`acme-corp.in`); attribution **`direct_attacker_infrastructure`** at 0.60
("throwaway mailbox"). In the UI note how the verdict rests entirely on identity
and language: the `url` and `entropy` pillars are both 0, the Impersonated risk
floor of 45 applies (`risk_floor_applied`), and the recommended action is to
verify with the CEO through a known channel rather than reply.

Note that the executive check needs `sarthak srivastava` in
`MAILTRACE_EXECUTIVES`. Without it the display-name spoof still fires on the
`CEO` title, so this sample keeps its Impersonated verdict either way - it is
sample 2, not this one, that changes when the `.env` is missing.

## Watching a campaign form

Verified this pass: on a clean store none of the five samples share indicators,
so each is ingested with `campaign_id: null` and stands alone. Upload any one of
them a second time (or paste it with a changed subject through "Paste raw
email"): the copy shares `ip:`, `sender:` and `domain:` indicators with the
first, a campaign is created, both cases link to it, and the Campaigns view
shows the merged graph with the campaign node and the shared pivot nodes. The
copy also scores higher than the original, because the `known_campaign_overlap`
finding raises the network pillar - that is correlation working, not a bug.
