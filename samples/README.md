# Sample messages

Five complete RFC 822 messages (multipart text + HTML, three to five `Received`
hops, 2026 dates, the `Authentication-Results` a real receiving MTA would add).
Together they exercise every analyzer. Nothing here is live malware: the
"executable" is an inert 100-byte `MZ` stub and the PDF is a one-line receipt.

**Before the demo** copy `.env.example` to `.env`. It sets
`MAILTRACE_ORG_DOMAINS=acme-corp.in` (the organisation every sample targets) and
`MAILTRACE_EXECUTIVES=ceo,cfo,managing director,sarthak srivastava`. Without it
the lookalike check in sample 2 and the executive check in sample 5 lose their
strongest signal. Expected values below are the design intent with live
enrichment on; offline mode (`MAILTRACE_ENABLE_NETWORK=false`) keeps the
verdicts but cannot flag Tor exits or geolocate.

| File | Expected category | Expected attribution | Origin IP (hop 0/1) |
|---|---|---|---|
| `phishing_sbi_kyc.eml` | Phishing | lookalike_domain | 45.148.10.72 (hosting) |
| `bec_payment_diversion.eml` | Fraud-Related | lookalike_domain (Tor origin) | 185.220.101.45 (Tor exit range) |
| `legit_transactional.eml` | Legitimate | legitimate_sender | 192.30.252.206 (GitHub MTA, US) |
| `fraud_lottery_advance_fee.eml` | Fraud-Related | direct_attacker_infrastructure | 197.210.85.12 (MTN Nigeria) |
| `impersonation_ceo_gift_cards.eml` | Impersonated | direct_attacker_infrastructure | 49.36.220.14 (Jio mobile, India) |

## phishing_sbi_kyc.eml

A State Bank of India KYC lure: display name "State Bank of India" on
`alerts@sbi-kyc-update.xyz`, Reply-To on Gmail, `Authentication-Results` with
`spf=fail`, `dkim=none`, `dmarc=fail`, an `X-PHP-Originating-Script` header and
top priority flags. The text demands KYC re-verification "within 24 hours" under
threat of suspension and a Rs. 999 penalty, and asks for account number, Aadhaar,
PAN and OTP. The HTML button and the "open this link" line both point to
`http://sbi-online-kyc-verify.xyz/login` while the visible anchor text reads
`https://onlinesbi.sbi`; the button URL also carries the recipient's address
base64-encoded in the query string. The chain runs localhost -> the attacker's
own `srv-mail01.sbi-kyc-update.xyz` (`45.148.10.72`, a hosting range) -> a
`.icu` bulk-mail relay (`193.42.33.118`) -> Google, with no TLS on the two
attacker-side hops. Expected: **Phishing** at critical risk, attribution
**lookalike_domain** (`sbi-kyc-update.xyz` is an extra-token imitation of the SBI
brand). In the UI look at the spoofing badge row (SPF, DMARC, Reply-To,
display name all red), the Links & Files tab (anchor/href mismatch, credential
keywords, suspicious `.xyz` TLD), the Content tab (urgency meter, credential
terms, `credential_harvesting` BEC card) and the Trace tab map with the origin
marker on hop 1.

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
Expected: **Fraud-Related** with the `payment_diversion` pattern at high
confidence, attribution **lookalike_domain** (with `acme-corp.in` configured);
live enrichment additionally raises the critical `tor_exit_node` finding. Offline,
the risk score settles exactly on the Fraud-Related floor of 60 (`risk_floor_applied`
finding), which is below the default `MAILTRACE_ALERT_THRESHOLD` of 70: this sample
appears in the case list but does not raise an alert (the SBI phishing sample does). In
the UI look at the Content tab (payment-diversion evidence phrases, secrecy and
urgency cues), the Domains & Infra tab (`acme-corp-in.com` flagged as a
lookalike, Tor flag on the origin) and the recommended action to verify the
bank change with the vendor on a previously known phone number.

## legit_transactional.eml

The control sample: a GitHub payment receipt from `noreply@github.com` with
`spf=pass`, `dkim=pass` (`d=github.com`) and `dmarc=pass` under a `p=REJECT`
policy, Reply-To identical to From, and a Message-ID on the sender's domain.
Hop 0 is GitHub's internal worker on a private `10.48.115.21` address, hop 1 is
`out-27.smtp.github.com` (`192.30.252.206`, the origin, in the United States)
delivering over TLS to Google. The body mentions payment, a receipt number and
"Visa ending in 4402", links once to `github.com`, and attaches a genuine PDF
(`%PDF` magic bytes match the declared type). Expected: **Legitimate**, low
risk, attribution **legitimate_sender**. It demonstrates that financial
vocabulary alone does not trigger a fraud verdict and that the authentication
badges, the single-country geo trail and the clean attachment inventory all
show green.

## fraud_lottery_advance_fee.eml

An advance-fee lottery scam: "Reserve Bank of India - RBI Prize Fund" on a
`yahoo.com` mailbox announces a Rs. 25,00,000 win, demands contact "within 72
hours", requests full name, Aadhaar, PAN, bank account and IFSC, and asks for a
"processing and insurance fee" of Rs. 4,850, adding a Nigerian (+234) WhatsApp
number and an instruction not to disclose the win. The subject is RFC 2047
base64-encoded UTF-8 (it contains the rupee sign), the mailer is PHPMailer, and
the attachment `claim_form.pdf.exe` is declared `application/pdf` but starts
with `MZ` executable bytes. SPF, DKIM and DMARC all pass for `yahoo.com`, so
authentication says nothing about the false identity. Hop 0 is an authenticated
Yahoo submission from `197.210.85.12` (MTN Nigeria, a residential mobile
network) by a host calling itself `DESKTOP-K8J2M1`. Expected: **Fraud-Related**
at critical risk, attribution **direct_attacker_infrastructure** (a throwaway
free-mail box posing as RBI). In the UI look at the attachment row (double
extension, MIME mismatch, executable magic -> critical), the origin geolocated
to Nigeria against the "held in Mumbai" claim, the `bulk_mailer` and
display-name-spoof findings, and the reward, secrecy and urgency cues.

## impersonation_ceo_gift_cards.eml

The first touch of an executive-impersonation thread (the gift-card request
follows once the victim replies). "Sarthak Srivastava (CEO)" writes from
`sarthak.ceo.office@gmail.com` to `priya.nair@acme-corp.in`: "Are you at your
desk? I need you to handle something urgent ... in a meeting with the board ...
can't take calls. Reply on this email only." There are no links and no
attachments, the body is under sixty words, and Gmail's SPF, DKIM and DMARC all
pass. Hop 0 is an `ESMTPSA` submission from `49.36.220.14` (Reliance Jio mobile
network, India) through `smtp.gmail.com`. Expected: **Impersonated** via the
`executive_impersonation` pattern and the display-name check (the name matches
a configured executive and the `CEO` title while the domain is not
`acme-corp.in`), attribution **direct_attacker_infrastructure** ("throwaway
mailbox"). In the UI note how the verdict rests entirely on identity and
language: the links and attachments components are zero, the Impersonated risk
floor of 45 applies, and the recommended action is to verify with the CEO
through a known channel rather than reply.

## Watching a campaign form

None of the five samples share indicators, so each starts as a standalone
case. Upload any one of them a second time (or paste it with a changed subject
through "Paste raw email"): the copy shares `ip:`, `sender:` and `domain:`
indicators with the first, a campaign is created, both cases link to it, and
the Campaigns view shows the merged graph with the campaign node and the shared
pivot nodes.
