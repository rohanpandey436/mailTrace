from __future__ import annotations

BRANDS: dict[str, list[str]] = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "hotmail.com", "microsoftonline.com",
                  "office365.com", "msn.com", "azure.com", "windows.com", "bing.com", "xbox.com", "onmicrosoft.com",
                  "office.net", "microsoftonline-p.com", "windowsazure.com"],
    "office365": ["microsoft.com", "office.com", "microsoftonline.com", "office365.com", "office.net"],
    "outlook": ["outlook.com", "microsoft.com", "live.com", "office.com"],
    "onedrive": ["onedrive.com", "live.com", "microsoft.com", "1drv.ms"],
    "sharepoint": ["sharepoint.com", "microsoft.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "google.co.in", "googleapis.com", "gstatic.com",
               "googleusercontent.com", "withgoogle.com", "youtube.com", "goo.gl", "google.co.uk"],
    "gmail": ["gmail.com", "google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com", "apple.news", "applecard.com", "apple.co"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazon.co.jp", "primevideo.com",
               "amazonpay.in", "amazon.de", "amazon.ca"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com", "facebookmail.com", "fb.me", "messenger.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "linkedin": ["linkedin.com", "licdn.com", "lnkd.in"],
    "twitter": ["twitter.com", "x.com", "t.co"],
    "dhl": ["dhl.com", "dhl.de", "dhl.co.in"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "bluedart": ["bluedart.com"],
    "dropbox": ["dropbox.com", "dropboxusercontent.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com", "adobe.io", "adobelogin.com", "acrobat.com"],
    "zoom": ["zoom.us", "zoom.com", "zoomgov.com"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "slack": ["slack.com", "slack-edge.com"],
    "okta": ["okta.com", "oktapreview.com"],
    "wetransfer": ["wetransfer.com", "we.tl"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in", "yonobusiness.sbi", "sbiyono.sbi"],
    "onlinesbi": ["onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"],
    "hdfc": ["hdfcbank.com", "hdfcbank.net", "hdfc.com", "hdfclife.com", "hdfcergo.com", "hdfcsec.com"],
    "hdfcbank": ["hdfcbank.com", "hdfcbank.net"],
    "icici": ["icicibank.com", "icicidirect.com", "iciciprulife.com", "icicilombard.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com", "axisdirect.in"],
    "kotak": ["kotak.com", "kotaksecurities.com", "kotak811.com"],
    "pnb": ["pnbindia.in"],
    "bankofbaroda": ["bankofbaroda.in", "bankofbaroda.com"],
    "canarabank": ["canarabank.com"],
    "paytm": ["paytm.com", "paytmbank.com", "paytmmoney.com"],
    "phonepe": ["phonepe.com"],
    "npci": ["npci.org.in"],
    "irctc": ["irctc.co.in"],
    "incometax": ["incometax.gov.in", "incometaxindia.gov.in"],
    "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "gst": ["gst.gov.in"],
    "digilocker": ["digilocker.gov.in"],
    "flipkart": ["flipkart.com"],
    "airtel": ["airtel.in", "airtel.com"],
    "jio": ["jio.com", "jiomart.com", "jiocinema.com"],
    "bsnl": ["bsnl.co.in", "bsnl.in"],
    "lic": ["licindia.in"],
    "rbi": ["rbi.org.in"],
    "sebi": ["sebi.gov.in"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "hsbc": ["hsbc.com", "hsbc.co.in"],
    "citibank": ["citi.com", "citibank.com"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "swiggy": ["swiggy.com", "swiggy.in"],
    "zomato": ["zomato.com"],
}

SHARED_MAIL_PROVIDERS: dict[str, str] = {
    "google.com": "Google", "googlemail.com": "Google", "gmail.com": "Google",
    "outlook.com": "Microsoft", "hotmail.com": "Microsoft", "live.com": "Microsoft", "office365.com": "Microsoft",
    "microsoft.com": "Microsoft", "microsoftonline.com": "Microsoft",
    "yahoo.com": "Yahoo", "yahoodns.net": "Yahoo", "yahoo.co.in": "Yahoo", "aol.com": "Yahoo", "ymail.com": "Yahoo",
    "icloud.com": "Apple", "apple.com": "Apple", "me.com": "Apple",
    "protonmail.ch": "Proton", "protonmail.com": "Proton", "proton.me": "Proton",
    "zoho.com": "Zoho", "zohomail.com": "Zoho", "zohomail.in": "Zoho", "zoho.in": "Zoho",
    "yandex.net": "Yandex", "yandex.ru": "Yandex", "yandex.com": "Yandex",
    "mail.ru": "Mail.ru", "qq.com": "Tencent", "163.com": "NetEase", "126.com": "NetEase",
    "rediffmail.com": "Rediff", "rediff.com": "Rediff", "gmx.net": "GMX", "gmx.com": "GMX", "web.de": "GMX",
    "tutanota.de": "Tuta", "tutanota.com": "Tuta", "tuta.io": "Tuta", "tuta.com": "Tuta",
    "amazonses.com": "Amazon SES", "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun", "mailgun.net": "Mailgun",
    "mcsv.net": "Mailchimp", "mcdlv.net": "Mailchimp", "rsgsv.net": "Mailchimp", "mandrillapp.com": "Mailchimp",
    "sparkpostmail.com": "SparkPost", "postmarkapp.com": "Postmark", "mtasv.net": "Postmark",
    "sendinblue.com": "Brevo", "brevo.com": "Brevo", "mailjet.com": "Mailjet", "smtp2go.com": "SMTP2GO",
    "pphosted.com": "Proofpoint", "ppe-hosted.com": "Proofpoint", "mimecast.com": "Mimecast",
    "messagelabs.com": "Symantec", "barracudanetworks.com": "Barracuda", "emailsrvr.com": "Rackspace",
    "secureserver.net": "GoDaddy", "hubspotemail.net": "HubSpot", "exacttarget.com": "Salesforce",
}


def shared_provider(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    for domain, provider in SHARED_MAIL_PROVIDERS.items():
        if host == domain or host.endswith("." + domain):
            return provider
    return ""

EXEC_TITLES: list[str] = [
    "ceo", "cfo", "coo", "cto", "cio", "chairman", "chairperson", "president",
    "managing director", "director", "founder", "vice president", "vp",
    "head of finance", "finance head", "accounts head", "hr head",
]

FREEMAIL_DOMAINS: set[str] = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.in", "ymail.com",
    "rocketmail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me", "pm.me",
    "zoho.com", "zohomail.in", "rediffmail.com", "rediff.com", "mail.com", "gmx.com",
    "gmx.net", "yandex.com", "yandex.ru", "mail.ru", "inbox.com", "fastmail.com",
    "tutanota.com", "tuta.io", "hushmail.com", "email.com", "usa.com", "sify.com",
    "indiatimes.com", "in.com",
}

DISPOSABLE_DOMAINS: set[str] = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.info", "10minutemail.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com", "yopmail.com", "getnada.com",
    "dispostable.com", "trashmail.com", "sharklasers.com", "maildrop.cc", "fakeinbox.com",
    "mohmal.com", "emailondeck.com", "mintemail.com", "tempr.email", "burnermail.io",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "t.ly", "rebrand.ly", "bl.ink", "lnkd.in",
    "s.id", "v.gd", "clck.ru", "urlz.fr", "shorte.st", "adf.ly", "qr.ae", "bitly.com",
}

SUSPICIOUS_TLDS: set[str] = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "icu",
    "cam", "rest", "monster", "cyou", "quest", "work", "click", "link", "surf", "fit",
    "loan", "win", "bid", "men", "date", "review", "stream", "download", "racing",
    "party", "trade", "science", "cricket", "accountant", "faith", "gdn", "ru", "su",
    "pw", "cc", "ws", "info", "online", "site", "website", "space", "tech", "live",
    "shop", "store", "vip", "sbs", "lol", "bond", "cfd", "one",
}

RISKY_EXTENSIONS: dict[str, str] = {
    "exe": "critical", "scr": "critical", "pif": "critical", "com": "critical", "bat": "critical",
    "cmd": "critical", "msi": "critical", "msp": "critical", "cpl": "critical", "dll": "critical",
    "vbs": "critical", "vbe": "critical", "js": "critical", "jse": "critical", "wsf": "critical",
    "wsh": "critical", "ps1": "critical", "psm1": "critical", "hta": "critical", "lnk": "critical",
    "url": "high", "reg": "high", "inf": "high", "chm": "high", "jar": "high", "apk": "high",
    "iso": "high", "img": "high", "vhd": "high", "vhdx": "high", "one": "high",
    "docm": "high", "xlsm": "high", "pptm": "high", "dotm": "high", "xltm": "high", "xlam": "high",
    "doc": "medium", "xls": "medium", "ppt": "medium", "rtf": "medium", "slk": "high", "iqy": "high",
    "zip": "medium", "rar": "medium", "7z": "medium", "gz": "medium", "tar": "medium", "ace": "high",
    "arj": "high", "cab": "high", "z": "medium", "bz2": "medium", "xz": "medium",
    "html": "medium", "htm": "medium", "shtml": "high", "svg": "medium", "xml": "low",
    "pdf": "low", "docx": "low", "xlsx": "low", "pptx": "low", "csv": "low", "txt": "info",
    "png": "info", "jpg": "info", "jpeg": "info", "gif": "info", "ics": "info", "vcf": "low",
}

ARCHIVE_EXTENSIONS: set[str] = {"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "ace", "arj", "cab", "z", "iso", "img"}
MACRO_EXTENSIONS: set[str] = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "doc", "xls", "ppt"}
EXECUTABLE_MAGIC: set[str] = {"pe", "elf", "macho", "msi", "script", "hta", "lnk"}

DNSBL_ZONES: list[str] = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "psbl.surriel.com",
]

COMMON_URL_HOSTS: set[str] = {
    "google.com", "www.google.com", "w3.org", "www.w3.org", "schema.org", "schemas.microsoft.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "youtube.com", "www.youtube.com", "facebook.com",
    "www.facebook.com", "twitter.com", "x.com", "linkedin.com", "www.linkedin.com", "instagram.com",
    "www.instagram.com", "apple.com", "www.apple.com", "play.google.com", "apps.apple.com",
    "microsoft.com", "www.microsoft.com", "unsubscribe.com", "list-manage.com", "mailchimp.com",
    "sendgrid.net", "gstatic.com", "googleusercontent.com", "cloudfront.net", "wikipedia.org",
}

HOMOGLYPHS: dict[str, str] = {
    "а": "a", "ą": "a", "ä": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "å": "a", "ā": "a",
    "ḃ": "b", "ƅ": "b",
    "с": "c", "ç": "c", "ć": "c", "ċ": "c", "č": "c",
    "ԁ": "d", "ď": "d", "đ": "d",
    "е": "e", "ё": "e", "é": "e", "è": "e", "ê": "e", "ë": "e", "ē": "e", "ė": "e", "ę": "e",
    "ġ": "g", "ğ": "g", "ģ": "g",
    "һ": "h", "ĥ": "h", "ħ": "h",
    "і": "i", "ı": "i", "í": "i", "ì": "i", "î": "i", "ï": "i", "ī": "i", "į": "i",
    "ј": "j", "ĵ": "j",
    "ķ": "k", "к": "k",
    "ӏ": "l", "ł": "l", "ļ": "l", "ľ": "l",
    "м": "m", "ṁ": "m",
    "ñ": "n", "ń": "n", "ņ": "n", "ň": "n", "п": "n",
    "о": "o", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o", "ø": "o", "ō": "o", "0": "o",
    "р": "p", "þ": "p",
    "ԛ": "q",
    "г": "r", "ŕ": "r", "ř": "r",
    "ѕ": "s", "ś": "s", "ş": "s", "š": "s", "ș": "s",
    "т": "t", "ţ": "t", "ť": "t", "ț": "t",
    "ú": "u", "ù": "u", "û": "u", "ü": "u", "ū": "u", "ų": "u", "ů": "u", "џ": "u",
    "ѵ": "v", "ν": "v",
    "ԝ": "w", "ŵ": "w",
    "х": "x", "×": "x",
    "у": "y", "ý": "y", "ÿ": "y", "ŷ": "y",
    "ź": "z", "ż": "z", "ž": "z",
    "1": "l", "3": "e", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
}

ASCII_CONFUSABLES: dict[str, list[str]] = {
    "l": ["1", "i", "|"], "i": ["1", "l", "j"], "o": ["0", "q"], "0": ["o"],
    "rn": ["m"], "m": ["rn", "nn"], "vv": ["w"], "w": ["vv"], "cl": ["d"], "d": ["cl"],
    "e": ["3"], "a": ["4", "@"], "s": ["5", "$"], "t": ["7"], "b": ["8"], "g": ["9", "q"],
}

URL_SUSPICIOUS_KEYWORDS: list[str] = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "password", "credential", "auth", "authenticate",
    "wallet", "recover", "unlock", "suspended", "billing", "invoice", "payment", "kyc",
    "aadhaar", "pan", "refund", "reward", "prize", "webmail", "owa", "sharepoint", "onedrive",
    "docusign", "dropbox", "office365", "o365", "outlook", "microsoft", "paypal", "apple",
    "netflix", "bank", "sbi", "hdfc", "icici", "upi",
]
