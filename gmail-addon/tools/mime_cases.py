from __future__ import annotations

import base64
import random

CRLF = b"\r\n"
LF = b"\n"
CR = b"\r"


def crlf(*lines: bytes) -> bytes:
    return CRLF.join(lines) + CRLF


def lf(*lines: bytes) -> bytes:
    return LF.join(lines) + LF


def b64lines(data: bytes, width: int = 76) -> bytes:
    encoded = base64.b64encode(data)
    return CRLF.join(encoded[start:start + width] for start in range(0, len(encoded), width))


RUPEE = "₹".encode("utf-8")
HINDI = "आपका खाता बंद हो जाएगा".encode("utf-8")
LATIN = "café déjà vu".encode("latin-1")
CP1252 = "“smart quotes” – dash €".encode("cp1252")
PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def header_cases() -> list[tuple[str, bytes]]:
    return [
        ("empty", b""),
        ("whitespace_only", b" \r\n\t\r\n"),
        ("not_a_message", b"not a message at all"),
        ("body_only_no_headers", crlf(b"", b"just a body", b"second line")),
        ("headers_only", crlf(b"From: a@example.com", b"Subject: only headers")),
        ("headers_only_no_final_newline", b"From: a@example.com\r\nSubject: no newline"),
        ("bare", crlf(b"Subject: bare", b"", b"body text")),
        ("lf_only", lf(b"From: a@example.com", b"Subject: unix", b"", b"line one", b"line two")),
        ("cr_only", CR.join([b"From: a@example.com", b"Subject: old mac", b"", b"line one", b"line two"]) + CR),
        ("mixed_newlines", b"From: a@example.com\nSubject: mixed\r\nX-A: 1\rX-B: 2\n\r\nbody\rmore\nend\r\n"),
        ("folded_space", crlf(b"Subject: folded", b" continuation", b"\tand tab", b"", b"body")),
        ("folded_empty_first", crlf(b"Subject:", b" continued", b"X-Also:", b"\tfolded", b"", b"body")),
        ("fold_lf", lf(b"Subject: folded", b"  two spaces", b"", b"body")),
        ("no_space_after_colon", crlf(b"Subject:tight", b"From:a@example.com", b"", b"body")),
        ("empty_value", crlf(b"Subject:", b"X-Empty: ", b"From: a@example.com", b"", b"body")),
        ("duplicates", crlf(b"X-Dup: one", b"X-Dup: two", b"x-dup: three", b"Subject: first", b"Subject: second", b"", b"body")),
        ("colon_first", crlf(b": no name", b"Subject: after", b"", b"body")),
        ("continuation_first", crlf(b" leading continuation", b"Subject: after", b"", b"body")),
        ("unix_from", crlf(b"From someone Mon Jan  1 00:00:00 2020", b"Subject: mbox", b"", b"body")),
        ("unix_from_middle", crlf(b"Subject: one", b"From someone Mon Jan  1 00:00:00 2020", b"X-After: two", b"", b"body")),
        ("unix_from_last", crlf(b"Subject: one", b"From the desk of the manager", b"", b"body")),
        ("greater_from_body", crlf(b"Subject: one", b"", b">From here", b"From there")),
        ("missing_separator", crlf(b"Subject: no blank line", b"this line has no colon so the body starts here", b"X-Not-A-Header: really")),
        ("space_before_colon", crlf(b"Subject : spaced", b"From: a@example.com", b"", b"body")),
        ("header_name_symbols", crlf(b"X-!#$%&'*+-.^_`|~: odd", b"Subject: ok", b"", b"body")),
        ("eight_bit_header_utf8", crlf(b"Subject: caf\xc3\xa9 " + RUPEE + b"500", b"From: R\xc3\xa9my <remy@example.com>", b"", b"body")),
        ("eight_bit_header_latin1", crlf(b"Subject: caf\xe9", b"From: Ren\xe9 <rene@example.com>", b"", b"body")),
        ("eight_bit_header_name", crlf(b"Subj\xe9ct: bad name", b"Subject: good", b"", b"body")),
        ("eight_bit_and_encoded", crlf(b"Subject: caf\xe9 =?utf-8?b?4oK5?= tail", b"", b"body")),
        ("control_chars_header", crlf(b"Subject: a\x0bb\x0cc\x1cd\x00e\x7ff", b"X-Next: ok", b"", b"body")),
        ("formfeed_colon_header", crlf(b"Subject: a\x0cInjected: value", b"", b"body")),
        ("long_header", crlf(b"Subject: " + b"word " * 40, b"X-Long: " + b"x" * 300, b"X-Comma: " + b"alpha,beta;gamma " * 20, b"", b"body")),
        ("long_header_no_space", crlf(b"X-Token: " + b"a" * 120 + b" " + b"b" * 120, b"", b"body")),
        ("trailing_space_header", crlf(b"Subject: trailing   ", b"X-Tab: value\t", b"", b"body")),
        ("tab_after_colon", crlf(b"Subject:\ttabbed", b"", b"body")),
        ("very_many_headers", crlf(*[b"X-H%d: v%d" % (i, i) for i in range(60)], b"", b"body")),
        ("header_crlf_fold_whitespace_only", crlf(b"Subject: a", b" ", b"\t", b" b", b"", b"body")),
        ("null_bytes", crlf(b"Subject: nul\x00here", b"", b"bo\x00dy")),
        ("received_chain", crlf(
            b"Received: from mail.example.com (mail.example.com [203.0.113.5])",
            b"\tby mx.google.com with ESMTPS id x1 for <a@b.in>",
            b"\t(version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);",
            b"\tMon, 7 Sep 2026 10:00:00 +0530 (IST)",
            b"Received: by 2002:a05:6a00:3d0c with SMTP id abc; Mon, 07 Sep 2026 04:30:01 -0000",
            b"Subject: hops", b"", b"body")),
    ]


def encoded_word_cases() -> list[tuple[str, bytes]]:
    subjects = [
        b"=?UTF-8?B?4oK5MjU=?=",
        b"=?utf-8?q?caf=C3=A9_au_lait?=",
        b"=?UTF-8?Q?=E2=82=B9500?= off =?UTF-8?Q?today?=",
        b"=?UTF-8?B?4oK5?= =?UTF-8?B?NTAw?=",
        b"=?UTF-8?B?4oK5?=  \t =?UTF-8?B?NTAw?=",
        b"=?UTF-8?B?4oK5?==?UTF-8?B?NTAw?=",
        b"plain =?UTF-8?B?4oK5?= middle =?iso-8859-1?q?caf=E9?= end",
        b"=?iso-8859-1?Q?caf=E9?=",
        b"=?ISO-8859-1?q?caf=e9?=",
        b"=?windows-1252?Q?=93quoted=94_=80?=",
        b"=?cp1252?Q?=81=8D=8F?=",
        b"=?koi8-r?B?8NLJ18XU?=",
        b"=?shift_jis?B?k/qWe4zq?=",
        b"=?iso-2022-jp?B?GyRCRnxLXDhsGyhC?=",
        b"=?euc-jp?B?xvzL3Ljs?=",
        b"=?gb2312?B?1tDOxA==?=",
        b"=?gbk?B?1tDOxA==?=",
        b"=?big5?B?pKSk5Q==?=",
        b"=?euc-kr?B?x9Gx27M=?=",
        b"=?utf-16?B?//5oAGkA?=",
        b"=?utf-16le?B?aABpAA==?=",
        b"=?utf-16be?B?AGgAaQ==?=",
        b"=?utf-32?B?//4AAGgAAAA=?=",
        b"=?utf-7?Q?+AOk-?=",
        b"=?us-ascii?Q?plain_ascii?=",
        b"=?ascii?Q?high=E9?=",
        b"=?x-unknown?Q?mystery=E9?=",
        b"=?unknown-8bit?Q?raw=E9=C3=A9?=",
        b"=?none?Q?quirk?= tail",
        b"=?utf-8*en?Q?language_tag?=",
        b"=?utf-8?Q?truncated=E2=82?=",
        b"=?utf-8?B?4oK?=",
        b"=?utf-8?B?4oK5M?=",
        b"=?utf-8?B?!!!!?=",
        b"=?utf-8?B??=",
        b"=?utf-8?Q??=",
        b"=?utf-8?Q?underscore_and=5Fescaped?=",
        b"=?utf-8?Q?equals=3Dsign?=",
        b"=?utf-8?Q?bad=ZZescape?=",
        b"=?utf-8?Q?lower=c3=a9?=",
        b"=?utf-8?X?unknown_encoding?=",
        b"=?utf-8?Q?no_end",
        b"=? not encoded ?=",
        b"=?utf-8?Q?a?b?=",
        b"=?utf-8?Q?question=3F?=",
        b"\"=?utf-8?Q?quoted?=\" <a@example.com>",
        b"=?utf-8?Q?(comment)?= text (=?utf-8?Q?inside?=)",
        b"=?utf-8?B?" + base64.b64encode(HINDI) + b"?=",
        b"=?utf-8?B?" + base64.b64encode(HINDI[:10]) + b"?= =?utf-8?B?" + base64.b64encode(HINDI[10:]) + b"?=",
        b"=?utf-8?B?" + base64.b64encode("emoji 😀 money 💰".encode("utf-8")) + b"?=",
        b"=?UTF-8?Q?Re:_=5BTicket_#1234=5D_?= =?UTF-8?Q?Your_account?=",
        b"=?latin-1?Q?alias=E9?= =?latin1?Q?alias=E9?= =?l1?Q?alias=E9?=",
        b"=?iso8859-15?Q?euro=A4?= =?iso-8859-15?Q?euro=A4?=",
        b"=?windows-1251?B?z/Do4uXy?=",
        b"=?tis-620?B?4LiX4LiU4Liq4Lit4Lia?=",
        b"=?utf8?Q?no_hyphen=C3=A9?=",
        b"=?UTF_8?Q?underscore=C3=A9?=",
        b"=?  utf-8  ?Q?spaces?=",
        b"=?utf-8?Q?tab\there?=",
        b"=?cp65001?Q?alias=C3=A9?=",
        b"=?macintosh?Q?mac=8E?=",
        b"=?ibm437?Q?dos=82?=",
        b"=?iso-8859-8-i?Q?hebrew=E0?=",
        b"=?x-mac-roman?Q?x=8E?=",
        b"=?hz-gb-2312?Q?~{VPND~}?=",
        b"=?rot13?Q?uryyb?=",
        b"=?base64?Q?aGk=?=",
        b"=?idna?Q?xn--caf-dma?=",
        b"=?unicode_escape?Q?=5Cu20b9?=",
    ]
    cases = []
    for index, subject in enumerate(subjects):
        cases.append((f"encoded_subject_{index}", crlf(b"Subject: " + subject, b"From: =?utf-8?Q?S=C3=A9nder?= <s@example.com>", b"", b"body")))
    cases.append(("encoded_folded", crlf(b"Subject: =?UTF-8?B?4oK5?=", b" =?UTF-8?B?NTAw?=", b"\t=?UTF-8?Q?_tail?=", b"", b"body")))
    cases.append(("encoded_folded_plain", crlf(b"Subject: first", b" =?UTF-8?B?4oK5?=", b" last", b"", b"body")))
    return cases


def parameter_cases() -> list[tuple[str, bytes]]:
    types = [
        b"text/plain",
        b"TEXT/PLAIN; CHARSET=UTF-8",
        b"text/plain; charset=\"utf-8\"",
        b"text/plain; charset = utf-8 ; format=flowed",
        b"text/plain;charset=utf-8;",
        b"text/plain; charset='utf-8'",
        b"text/plain; charset*=utf-8''utf-8",
        b"text/plain; charset*=''iso-8859-1",
        b"text/plain; charset*0=utf; charset*1=-8",
        b"text/plain; charset=caf\xe9",
        b"text/plain; charset=",
        b"text/plain; charset",
        b"text/plain; =novalue",
        b"text/plain; ; ;",
        b"text/plain; name=\"a;b.txt\"; charset=utf-8",
        b"text/plain; name=\"quote\\\"inside.txt\"",
        b"text/plain; name=\"back\\\\slash.txt\"",
        b"text/plain; name=\"unterminated; charset=utf-8",
        b"text/plain; name=<angle.txt>",
        b"text/plain; name=(comment) real.txt",
        b"text",
        b"text/",
        b"/plain",
        b"text/plain/extra",
        b"",
        b";charset=utf-8",
        b"text/html; charset=windows-1252",
        b"application/octet-stream; name=data.bin",
        b"application/octet-stream; name*=utf-8''r%C3%A9sum%C3%A9.pdf",
        b"application/octet-stream; name*=utf-8'en'r%C3%A9sum%C3%A9.pdf",
        b"application/octet-stream; name*=iso-8859-1''caf%E9.txt",
        b"application/octet-stream; name*=x-unknown''caf%E9.txt",
        b"application/octet-stream; name*=''caf%E9.txt",
        b"application/octet-stream; name*=caf%E9.txt",
        b"application/octet-stream; name*0=\"long\"; name*1=\"er-na\"; name*2=\"me.txt\"",
        b"application/octet-stream; name*1=\"second\"; name*0=\"first\"",
        b"application/octet-stream; name*1=\"no-zero\"; name*2=\"at-all\"",
        b"application/octet-stream; name*0*=utf-8''r%C3%A9; name*1*=sum%C3%A9; name*2=.pdf",
        b"application/octet-stream; name*0*=utf-8''a%20b; name*1=\"%20c\"",
        b"application/octet-stream; name*=utf-8''bad%ZZescape%2",
        b"application/octet-stream; name*=utf-8''%E2%82",
        b"application/octet-stream; name*=utf-8''%e2%82%b9lower",
        b"application/octet-stream; name=\"=?utf-8?B?4oK5LnBkZg==?=\"",
        b"application/octet-stream; name==?utf-8?Q?bare=E2=82=B9.pdf?=",
        b"application/octet-stream; name=\"..\\\\..\\\\windows\\\\evil.exe\"",
        b"application/octet-stream; name=\"../../etc/passwd\"",
        b"application/octet-stream; name=\"C:\\\\Users\\\\me\\\\invoice.pdf.exe\"",
        b"application/octet-stream; name=\"  spaced name .txt  \"",
        b"application/octet-stream; name=\"ctrl\x01\x02chars\x7f.txt\"",
        b"application/octet-stream; name=\"" + b"n" * 300 + b".txt\"",
        b"application/octet-stream; name=\"multi.part.name.tar.gz\"",
        b"application/octet-stream; name=\"noextension\"",
        b"application/octet-stream; name=\"trailingdot.\"",
        b"application/octet-stream; name=\".hidden\"",
        b"application/octet-stream; name=\"UPPER.PDF\"",
        b"application/octet-stream; name=\"unicode-ext.\xd0\xbf\xd0\xb4\xd1\x84\"",
        b"application/octet-stream; name=\"long.extensionistoolong\"",
        b"application/octet-stream; name=\"sym.p-d\"",
        b"application/octet-stream; NAME=\"upper-param.txt\"",
        b"application/octet-stream; name=first.txt; name=second.txt",
    ]
    cases = []
    for index, ctype in enumerate(types):
        cases.append((f"content_type_{index}", crlf(b"Subject: params", b"Content-Type: " + ctype, b"", b"body " + RUPEE, b"second")))
    dispositions = [
        b"attachment; filename=\"report.pdf\"",
        b"attachment; filename=report.pdf",
        b"ATTACHMENT; FILENAME=\"UPPER.PDF\"",
        b"attachment",
        b"attachment;",
        b"inline; filename=\"inline.png\"",
        b"inline",
        b"  attachment ; filename = \"spaced.txt\"",
        b"attachment; filename*=UTF-8''%E2%82%B9%20invoice.pdf",
        b"attachment; filename*0*=UTF-8''%E2%82%B9; filename*1*=%20invoice; filename*2=\".pdf\"",
        b"attachment; filename=\"fallback.txt\"; filename*=UTF-8''preferred%20name.txt",
        b"attachment; filename*=UTF-8''preferred.txt; filename=\"fallback.txt\"",
        b"attachment; filename=\"=?UTF-8?B?4oK5IGludm9pY2UucGRm?=\"",
        b"attachment; filename=\"=?iso-8859-1?Q?caf=E9.txt?=\"",
        b"attachment; filename=\"\"",
        b"attachment; filename=",
        b"attachment; filename=\"   \"",
        b"attachment; size=1234; filename=\"after-size.bin\"",
        b"form-data; name=\"field\"; filename=\"upload.txt\"",
        b"attachment; filename=caf\xc3\xa9.txt",
        b"attachment; filename=\"caf\xe9.txt\"",
        b"attachment; filename=\"a\\\"b.txt\"",
        b"attachment; filename=\"semi;colon.txt\"",
        b"attachment; filename=\"new\r\n line.txt\"",
        b"filename=\"no-disposition-type.txt\"",
        b"\"attachment\"; filename=\"quoted-type.txt\"",
        b"attachment(comment); filename=\"comment.txt\"",
    ]
    for index, disposition in enumerate(dispositions):
        cases.append((f"disposition_{index}", crlf(
            b"Subject: disposition",
            b"Content-Type: application/pdf; name=\"from-type.pdf\"",
            b"Content-Disposition: " + disposition,
            b"Content-Transfer-Encoding: base64",
            b"",
            b64lines(PDF),
        )))
        cases.append((f"disposition_text_{index}", crlf(
            b"Subject: disposition on text",
            b"Content-Type: text/plain; charset=utf-8",
            b"Content-Disposition: " + disposition,
            b"",
            b"text body",
        )))
    return cases


def encoding_cases() -> list[tuple[str, bytes]]:
    encoded_pdf = base64.b64encode(PDF)
    bodies: list[tuple[bytes, bytes]] = [
        (b"base64", b64lines(PDF)),
        (b"BASE64", b64lines(PDF)),
        (b" base64 ", b64lines(PDF)),
        (b"base64 (comment)", b64lines(PDF)),
        (b"base64", encoded_pdf),
        (b"base64", LF.join(encoded_pdf[i:i + 20] for i in range(0, len(encoded_pdf), 20))),
        (b"base64", b" ".join(encoded_pdf[i:i + 8] for i in range(0, len(encoded_pdf), 8))),
        (b"base64", encoded_pdf.rstrip(b"=")),
        (b"base64", encoded_pdf[:-3]),
        (b"base64", encoded_pdf + b"===="),
        (b"base64", encoded_pdf[:20] + b"!!**" + encoded_pdf[20:]),
        (b"base64", encoded_pdf[:21]),
        (b"base64", b"A"),
        (b"base64", b"=="),
        (b"base64", b""),
        (b"base64", b"not base64 at all \xff\xfe"),
        (b"base64", encoded_pdf[:16] + b"==" + encoded_pdf[16:]),
        (b"base64", base64.urlsafe_b64encode(bytes(range(240, 256)) * 3)),
        (b"quoted-printable", b"hello =E2=82=B9 world=\r\ncontinued =3D done"),
        (b"Quoted-Printable", b"lower =e2=82=b9 hex"),
        (b"quoted-printable", b"bad =ZZ escape and trailing ="),
        (b"quoted-printable", b"soft break with spaces=  \r\nnext"),
        (b"quoted-printable", b"soft break lf=\nnext"),
        (b"quoted-printable", b"soft break cr=\rnext line\nafter"),
        (b"quoted-printable", b"double == equals =\r\n=\r\n"),
        (b"quoted-printable", b"under_score stays"),
        (b"quoted-printable", b"raw 8bit \xe2\x82\xb9 inside"),
        (b"quoted-printable", b"=0D=0A encoded crlf =00 nul"),
        (b"7bit", b"seven bit text"),
        (b"8bit", b"eight bit " + RUPEE),
        (b"binary", bytes(range(256))),
        (b"x-unknown", b"unknown encoding " + RUPEE),
        (b"", b"empty encoding header"),
        (b"base64; charset=utf-8", b64lines(PDF)),
        (b"x-uuencode", b"begin 644 file.txt\r\n+:&5L;&\\@=V]R;&0*\r\n`\r\nend\r\n"),
        (b"uuencode", b"begin 644 file.txt\n+:&5L;&\\@=V]R;&0*\n`\nend\n"),
        (b"uue", b"no begin line here"),
        (b"x-uue", b"begin 644 file.txt\r\n+:&5L;&\\@=V]R;&0*\r\n\r\nend\r\n"),
        (b"x-uuencode", b"begin 999 file.txt\r\n+:&5L;&\\@=V]R;&0*\r\nend\r\n"),
        (b"x-uuencode", b"begin 644 file.txt\r\n+:&5L;&\\@=V]R;&0* trailing junk\r\nend\r\n"),
    ]
    cases = []
    for index, (encoding, body) in enumerate(bodies):
        cases.append((f"transfer_{index}", crlf(
            b"Subject: transfer encoding",
            b"Content-Type: application/octet-stream",
            b"Content-Transfer-Encoding: " + encoding,
            b"",
        ) + body))
        cases.append((f"transfer_text_{index}", crlf(
            b"Subject: transfer encoding text",
            b"Content-Type: text/plain; charset=utf-8",
            b"Content-Transfer-Encoding: " + encoding,
            b"",
        ) + body + CRLF))
    charsets: list[tuple[bytes, bytes]] = [
        (b"utf-8", b"rupee " + RUPEE + b" " + HINDI),
        (b"UTF-8", b"invalid \xff\xfe bytes " + RUPEE[:2]),
        (b"utf8", HINDI),
        (b"us-ascii", b"claims ascii " + RUPEE),
        (b"ascii", b"pure ascii"),
        (b"iso-8859-1", LATIN),
        (b"latin1", LATIN),
        (b"iso-8859-15", "euro € sign".encode("iso-8859-15")),
        (b"windows-1252", CP1252),
        (b"cp1252", b"undefined \x81\x8d\x8f\x90\x9d bytes"),
        (b"windows-1251", "Привет".encode("cp1251")),
        (b"koi8-r", "Привет".encode("koi8-r")),
        (b"iso-8859-2", "Łódź".encode("iso-8859-2")),
        (b"iso-8859-7", "Ελληνικά".encode("iso-8859-7")),
        (b"windows-1256", "مرحبا".encode("cp1256")),
        (b"tis-620", "สวัสดี".encode("tis-620")),
        (b"shift_jis", "日本語のテキスト".encode("shift_jis")),
        (b"iso-2022-jp", "日本語のテキスト".encode("iso-2022-jp")),
        (b"euc-jp", "日本語のテキスト".encode("euc-jp")),
        (b"gb2312", "中文文本".encode("gb2312")),
        (b"gbk", "中文文本".encode("gbk")),
        (b"gb18030", "中文文本 €".encode("gb18030")),
        (b"big5", "中文文本".encode("big5")),
        (b"euc-kr", "한국어".encode("euc-kr")),
        (b"utf-16", "utf sixteen ₹".encode("utf-16")),
        (b"utf-16le", "utf sixteen ₹".encode("utf-16-le")),
        (b"utf-16be", "utf sixteen ₹ 😀".encode("utf-16-be")),
        (b"utf-16", b"\xff\xfeo\x00d\x00d"),
        (b"utf-16", b"\x00\xd8\x00\xd8a\x00"),
        (b"utf-32", "utf thirty two ₹".encode("utf-32")),
        (b"utf-8-sig", b"\xef\xbb\xbfwith bom"),
        (b"x-nonexistent", b"mystery bytes \xe9\xff"),
        (b"x-nonexistent", b"mystery but utf8 " + RUPEE),
        (b"unknown-8bit", b"eight bit \xe9"),
        (b"macintosh", "mac café".encode("mac-roman")),
        (b"ibm850", "dos café".encode("cp850")),
        (b"utf-7", b"+AOk- utf seven"),
    ]
    for index, (charset, body) in enumerate(charsets):
        cases.append((f"charset_plain_{index}", crlf(
            b"Subject: charset",
            b"Content-Type: text/plain; charset=" + charset,
            b"Content-Transfer-Encoding: 8bit",
            b"",
        ) + body + CRLF))
        cases.append((f"charset_html_{index}", crlf(
            b"Subject: charset html",
            b"Content-Type: text/html; charset=\"" + charset + b"\"",
            b"Content-Transfer-Encoding: base64",
            b"",
            b64lines(b"<p>" + body + b"</p><a href=\"https://example.com/x\">link</a>"),
        )))
    cases.append(("no_charset_utf8", crlf(b"Subject: none", b"Content-Type: text/plain", b"", b"rupee " + RUPEE)))
    cases.append(("no_charset_latin1", crlf(b"Subject: none", b"Content-Type: text/plain", b"", LATIN)))
    cases.append(("no_content_type_8bit", crlf(b"Subject: none", b"", b"rupee " + RUPEE, LATIN)))
    return cases


def multipart_cases() -> list[tuple[str, bytes]]:
    text_part = crlf(b"Content-Type: text/plain; charset=utf-8", b"", b"plain part " + RUPEE)
    html_part = crlf(b"Content-Type: text/html; charset=utf-8", b"", b"<p>html part</p><a href=\"https://example.com/login\">Sign in</a>")
    pdf_part = crlf(
        b"Content-Type: application/pdf; name=\"report.pdf\"",
        b"Content-Disposition: attachment; filename=\"report.pdf\"",
        b"Content-Transfer-Encoding: base64",
        b"",
        b64lines(PDF),
    )
    image_part = crlf(
        b"Content-Type: image/png",
        b"Content-ID: <logo@example.com>",
        b"Content-Transfer-Encoding: base64",
        b"",
        b64lines(PNG),
    )
    inner_message = crlf(
        b"From: inner@example.com",
        b"To: someone@example.org",
        b"Subject: forwarded " + b"very long subject " * 8,
        b"Date: Mon, 7 Sep 2026 10:00:00 +0530",
        b"Content-Type: text/plain; charset=utf-8",
        b"",
        b"inner body " + RUPEE,
    )

    def multipart(subtype: bytes, boundary: bytes, parts: list[bytes], preamble: bytes = b"", epilogue: bytes = b"", close: bool = True, quote: bool = True) -> bytes:
        value = b"\"" + boundary + b"\"" if quote else boundary
        out = crlf(b"Subject: multipart", b"MIME-Version: 1.0", b"Content-Type: multipart/" + subtype + b"; boundary=" + value, b"")
        out += preamble
        for part in parts:
            out += b"--" + boundary + CRLF + part
        if close:
            out += b"--" + boundary + b"--" + CRLF
        return out + epilogue

    alternative = multipart(b"alternative", b"INNER", [text_part, html_part])
    nested = b"\r\n".join(alternative.split(b"\r\n")[2:])
    cases = [
        ("alternative", alternative),
        ("mixed_with_attachment", multipart(b"mixed", b"OUTER", [text_part, pdf_part])),
        ("nested", multipart(b"mixed", b"OUTER", [nested, pdf_part], preamble=crlf(b"This is a multi-part message."), epilogue=crlf(b"epilogue text"))),
        ("related_inline_image", multipart(b"related", b"REL", [html_part, image_part])),
        ("unquoted_boundary", multipart(b"mixed", b"simple-boundary_42", [text_part], quote=False)),
        ("boundary_with_spaces", multipart(b"mixed", b"a boundary with spaces", [text_part])),
        ("boundary_special_chars", multipart(b"mixed", b"=_Part_123'()+_,-./:=?", [text_part, html_part])),
        ("no_close", multipart(b"mixed", b"OPEN", [text_part, pdf_part], close=False)),
        ("no_parts", multipart(b"mixed", b"EMPTY", [])),
        ("no_parts_no_close", multipart(b"mixed", b"EMPTY", [], close=False)),
        ("preamble_only", multipart(b"mixed", b"NEVER", [], preamble=crlf(b"the boundary never appears", b"at all"), close=False)),
        ("preamble_lf", multipart(b"mixed", b"B", [text_part], preamble=b"preamble line\n")),
        ("preamble_no_newline_before_boundary", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--B", b"Content-Type: text/plain", b"", b"x", b"--B--")),
        ("epilogue_variants", multipart(b"mixed", b"B", [text_part], epilogue=b"\r\n\r\nepilogue after blank\r\n")),
        ("epilogue_no_newline", multipart(b"mixed", b"B", [text_part], epilogue=b"tail")),
        ("close_without_newline", multipart(b"mixed", b"B", [text_part])[:-2]),
        ("boundary_trailing_space", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--B  ", b"Content-Type: text/plain", b"", b"one", b"--B \t", b"", b"two", b"--B-- ", b"tail")),
        ("boundary_trailing_garbage", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--B garbage", b"Content-Type: text/plain", b"", b"one", b"--Bx", b"--B", b"", b"two", b"--B--x", b"--B--")),
        ("boundary_prefix_collision", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--BB", b"--B", b"", b"--BB inside", b"--B--")),
        ("double_boundary", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--B", b"--B", b"--B", b"Content-Type: text/plain", b"", b"after triple", b"--B--")),
        ("boundary_then_close", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--B", b"--B--", b"Content-Type: text/plain", b"", b"swallowed close")),
        ("boundary_at_eof", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\none\r\n--B"),
        ("boundary_at_eof_newline", b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\none\r\n--B\r\n"),
        ("empty_boundary", crlf(b"Content-Type: multipart/mixed; boundary=\"\"", b"", b"--", b"Content-Type: text/plain", b"", b"one", b"-- signature", b"----")),
        ("missing_boundary_param", crlf(b"Content-Type: multipart/mixed", b"", b"--B", b"Content-Type: text/plain", b"", b"one", b"--B--")),
        ("missing_boundary_8bit", crlf(b"Content-Type: multipart/mixed", b"", b"raw " + RUPEE)),
        ("boundary_case_sensitive", crlf(b"Content-Type: multipart/mixed; boundary=Bound", b"", b"--bound", b"--Bound", b"", b"x", b"--BOUND--", b"--Bound--")),
        ("boundary_rfc2231", crlf(b"Content-Type: multipart/mixed; boundary*=utf-8''B%20x", b"", b"--B x", b"", b"one", b"--B x--")),
        ("boundary_continued", crlf(b"Content-Type: multipart/mixed; boundary*0=\"PART\"; boundary*1=\"-TWO\"", b"", b"--PART-TWO", b"", b"one", b"--PART-TWO--")),
        ("multipart_base64_cte", crlf(b"Content-Type: multipart/mixed; boundary=B", b"Content-Transfer-Encoding: base64", b"", b"--B", b"", b"one", b"--B--")),
        ("parts_without_headers", crlf(b"Content-Type: multipart/mixed; boundary=B", b"", b"--B", b"", b"headerless one", b"--B", b"headerless no blank", b"--B--")),
        ("part_lf_mixed", b"Content-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/plain\n\none\r\n--B\r\n\r\ntwo\n--B--\n"),
        ("unterminated_inner", crlf(
            b"Content-Type: multipart/mixed; boundary=OUT", b"",
            b"--OUT", b"Content-Type: multipart/alternative; boundary=IN", b"",
            b"--IN", b"Content-Type: text/plain", b"", b"inner text",
            b"--OUT", b"Content-Type: text/plain", b"", b"outer text",
            b"--OUT--")),
        ("inner_same_boundary", crlf(
            b"Content-Type: multipart/mixed; boundary=SAME", b"",
            b"--SAME", b"Content-Type: multipart/alternative; boundary=SAME", b"",
            b"--SAME", b"Content-Type: text/plain", b"", b"which level",
            b"--SAME--", b"--SAME--")),
        ("digest", crlf(
            b"Content-Type: multipart/digest; boundary=D", b"",
            b"--D", b"", b"Subject: digest one", b"", b"first",
            b"--D", b"Content-Type: text/plain", b"", b"explicit type",
            b"--D--")),
        ("rfc822_attachment", multipart(b"mixed", b"OUTER", [text_part, crlf(b"Content-Type: message/rfc822", b"Content-Disposition: attachment; filename=\"forwarded.eml\"", b"") + inner_message])),
        ("rfc822_lf", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"") + inner_message.replace(CRLF, LF)])),
        ("rfc822_nested_multipart", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"") + multipart(b"alternative", b"DEEP", [text_part, html_part], preamble=crlf(b"pre"), epilogue=crlf(b"epi"))])),
        ("rfc822_signed", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"") + multipart(b"signed", b"SIG", [crlf(b"Content-Type: text/plain", b"X-Long: " + b"token " * 30, b"", b"signed text"), crlf(b"Content-Type: application/pkcs7-signature", b"", b"c2ln")])])),
        ("rfc822_base64", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"Content-Transfer-Encoding: base64", b"", b64lines(inner_message))])),
        ("rfc822_top_level", crlf(b"Content-Type: message/rfc822", b"") + inner_message),
        ("rfc822_empty", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"")])),
        ("rfc822_8bit_headers", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"Subject: caf\xc3\xa9 " + b"long " * 30, b"X-Folded: a", b" b", b"", b"body \xff")])),
        ("rfc822_formfeed_header", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"Subject: a\x0cInjected: value", b"", b"body")])),
        ("rfc822_vertical_tab_header", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"Subject: a\x0bb", b"", b"body")])),
        ("rfc822_broken_multipart_8bit", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"Content-Type: multipart/mixed", b"", b"raw " + RUPEE)])),
        ("rfc822_broken_multipart_ascii", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"Content-Type: multipart/mixed; boundary=NEVER", b"", b"no boundary here", b"second line")])),
        ("rfc822_unix_from", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"From sender Mon Jan  1 00:00:00 2020", b"Subject: mbox inner", b"", b"From here", b"body")])),
        ("rfc822_named_by_type", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822; name=\"original.eml\"", b"") + inner_message])),
        ("rfc822_whitespace_headers", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"Subject:   spaced   out   value  ", b"X-Tabs:\ta\t\tb", b"X-Empty:", b"", b"body")])),
        ("rfc822_long_unbreakable", multipart(b"mixed", b"OUTER", [crlf(b"Content-Type: message/rfc822", b"", b"X-Long: " + b"a" * 200, b"X-Url: https://example.com/" + b"p" * 100 + b"?q=1;r=2,s=3", b"References: " + b" ".join(b"<id%d@example.com>" % i for i in range(12)), b"", b"body")])),
        ("delivery_status", multipart(b"report", b"REP", [
            text_part,
            crlf(b"Content-Type: message/delivery-status", b"", b"Reporting-MTA: dns; mx.example.com", b"", b"Final-Recipient: rfc822; a@example.org", b"Action: failed", b"Status: 5.1.1", b"", b"Final-Recipient: rfc822; b@example.org", b"Action: delayed"),
            crlf(b"Content-Type: text/rfc822-headers", b"", b"Subject: original", b"From: a@example.com"),
        ])),
        ("delivery_status_top", crlf(b"Content-Type: message/delivery-status", b"", b"Status: 5.0.0")),
        ("delivery_status_empty", crlf(b"Content-Type: message/delivery-status", b"")),
        ("message_partial", crlf(b"Content-Type: message/partial; id=\"abc\"; number=1; total=2", b"", b"Subject: part one", b"", b"partial body")),
        ("message_global", crlf(b"Content-Type: message/global", b"", b"Subject: global", b"", b"body")),
        ("message_external_body", crlf(b"Content-Type: message/external-body; access-type=URL; URL=\"https://example.com/file\"", b"", b"Content-Type: application/pdf", b"", b"")),
        ("odd_main_types", multipart(b"mixed", b"OUTER", [
            crlf(b"Content-Type: multipart_signed/x", b"", b"treated as text"),
            crlf(b"Content-Type: message_delivery_status/x", b"", b"also text"),
            crlf(b"Content-Type: message-x/y", b"", b"hyphen"),
            crlf(b"Content-Type: x-custom/thing", b"", b"custom"),
        ])),
        ("many_attachments", multipart(b"mixed", b"MANY", [text_part] + [
            crlf(b"Content-Type: " + ctype, b"Content-Transfer-Encoding: base64", b"", b64lines(b"payload %d " % i + bytes(range(i, i + 40))))
            for i, ctype in enumerate([
                b"application/pdf", b"application/zip", b"image/jpeg", b"image/png", b"image/gif", b"text/csv", b"text/calendar",
                b"application/msword", b"application/vnd.ms-excel", b"application/x-msdownload", b"application/javascript",
                b"application/json", b"audio/mpeg", b"video/mp4", b"application/x-unknown-thing", b"application/octet-stream",
                b"text/x-python", b"application/xml", b"application/rtf", b"image/svg+xml", b"text/html", b"text/plain",
            ])
        ])),
        ("attachment_is_text", multipart(b"mixed", b"OUTER", [
            crlf(b"Content-Type: text/plain; name=\"notes.txt\"", b"", b"named text part"),
            crlf(b"Content-Type: text/html", b"Content-Disposition: attachment", b"", b"<p>attached html</p>"),
            crlf(b"Content-Type: text/plain", b"Content-Disposition: inline", b"", b"inline text"),
            crlf(b"Content-Type: TEXT/PLAIN", b"", b"upper type"),
            crlf(b"", b"no headers at all"),
        ])),
        ("two_text_bodies", multipart(b"mixed", b"OUTER", [text_part, text_part, html_part, html_part])),
        ("html_only", crlf(b"Subject: html only", b"Content-Type: text/html; charset=utf-8", b"", b"<html><body><h1>Title</h1><p>Para &amp; more</p><ul><li>one</li><li>two</li></ul></body></html>")),
        ("deep_nesting", deep(12)),
        ("very_deep_nesting", deep(60)),
    ]
    return cases


def deep(levels: int) -> bytes:
    out = b""
    for level in range(levels):
        out += crlf(b"Content-Type: multipart/mixed; boundary=L%d" % level, b"", b"--L%d" % level)
    out += crlf(b"Content-Type: text/plain", b"", b"bottom")
    for level in reversed(range(levels)):
        out += crlf(b"--L%d--" % level)
    return out


def address_cases() -> list[tuple[str, bytes]]:
    senders = [
        b"a@example.com",
        b"<a@example.com>",
        b"Alice <a@example.com>",
        b"\"Alice Smith\" <a@example.com>",
        b"\"Smith, Alice\" <a@example.com>",
        b"Alice Smith <A.Smith@EXAMPLE.COM>",
        b"a@example.com (Alice Smith)",
        b"Alice (nick) Smith <a@example.com>",
        b"(comment) a@example.com",
        b"\"Alice \\\"Al\\\" Smith\" <a@example.com>",
        b"\"back\\\\slash\" <a@example.com>",
        b"'Single Quoted' <a@example.com>",
        b"=?utf-8?Q?S=C3=A9nder_Name?= <a@example.com>",
        b"=?utf-8?B?4KSw4KS+4KSc?= <raj@example.in>",
        b"\"=?utf-8?Q?Quoted_Encoded?=\" <a@example.com>",
        b"SBI Support <support@sbi-secure.example.top>",
        b"\"support@sbi.co.in\" <attacker@evil.example>",
        b"support@sbi.co.in <attacker@evil.example>",
        b"\"PayPal <service@paypal.com>\" <attacker@evil.example>",
        b"a@example.com, b@example.com",
        b"Alice <a@example.com>, Bob <b@example.com>",
        b"Group: a@example.com, b@example.com;",
        b"undisclosed-recipients:;",
        b"a@[192.168.1.1]",
        b"Alice <a@[IPv6:2001:db8::1]>",
        b"a@example",
        b"a@",
        b"@example.com",
        b"no at sign",
        b"",
        b"   ",
        b"<>",
        b"< a@example.com >",
        b"<a @ example . com>",
        b"a.b.c@example.com",
        b"\"a b\"@example.com",
        b"a+tag@example.com",
        b"a%b@example.com",
        b"o'neil@example.com",
        b"a=b@example.com",
        b"a@b@example.com",
        b"Alice <a@example.com> extra",
        b"Alice <a@example.com",
        b"Alice a@example.com>",
        b"Alice <<a@example.com>>",
        b"<a@example.com> Alice",
        b"Alice <@route1,@route2:a@example.com>",
        b"a@example.com;",
        b";a@example.com",
        b"a@example.com,",
        b",a@example.com",
        b"(unclosed comment a@example.com",
        b"closed) comment a@example.com",
        b"\"unclosed quote <a@example.com>",
        b"Alice <a@example.com>, (only comment), Bob <b@example.com>",
        b"caf\xc3\xa9 <cafe@example.com>",
        b"R\xe9ne <rene@example.com>",
        b"a@ex\xc3\xa4mple.com",
        b"Alice\x01\x02 <a@example.com>",
        b"Alice\tTabbed <a@example.com>",
        b"Alice\r\n Folded <a@example.com>",
        b"a@example.com\r\n\t,b@example.com",
        b"\"a@example.com\"",
        b"mailto:a@example.com",
        b"Alice [Team] <a@example.com>",
        b"Alice <a@example.com[>",
        b"Alice: <a@example.com>",
        b"A.l.i.c.e <a@example.com>",
        b"Alice. <a@example.com>",
        b".Alice <a@example.com>",
        b"Dr. Alice Smith, PhD <a@example.com>",
        b"\"\" <a@example.com>",
        b"\" \" <a@example.com>",
        b"xn--caf-dma@xn--caf-dma.example",
        b"very.long.local.part.that.goes.on.and.on.and.on@" + b"sub." * 20 + b"example.com",
    ]
    cases = []
    for index, sender in enumerate(senders):
        cases.append((f"address_{index}", crlf(
            b"From: " + sender,
            b"To: " + sender,
            b"Cc: " + sender + b", second@example.org",
            b"Reply-To: " + sender,
            b"Return-Path: " + sender,
            b"Subject: addresses",
            b"",
            b"body",
        )))
    cases.append(("address_multiple_headers", crlf(
        b"From: first@example.com", b"From: second@example.com",
        b"To: a@example.com", b"To: b@example.com", b"TO: c@example.com",
        b"Cc: d@example.com", b"cc: e@example.com",
        b"Reply-To: r1@example.com", b"Reply-To: r2@example.com",
        b"Return-Path: <bounce@example.com>", b"Return-Path: <other@example.com>",
        b"Message-ID: <first@id>", b"Message-Id: <second@id>",
        b"X-Mailer: First Mailer", b"User-Agent: Agent",
        b"", b"body")))
    cases.append(("user_agent_only", crlf(b"User-Agent: Mozilla Thunderbird", b"Message-ID:   < spaced@id >  ", b"", b"body")))
    cases.append(("mailer_encoded", crlf(b"X-Mailer: =?utf-8?Q?M=C3=A4iler?= 1.0", b"Message-ID: no-brackets@id", b"", b"body")))
    return cases


def date_cases() -> list[tuple[str, bytes]]:
    dates = [
        b"Mon, 7 Sep 2026 10:00:00 +0530",
        b"Mon, 07 Sep 2026 10:00:00 +0530 (IST)",
        b"7 Sep 2026 10:00:00 +0530",
        b"Mon, 7 Sep 2026 10:00 +0530",
        b"Mon, 7 Sep 2026 10:00:00 GMT",
        b"Mon, 7 Sep 2026 10:00:00 UT",
        b"Mon, 7 Sep 2026 10:00:00 UTC",
        b"Mon, 7 Sep 2026 10:00:00 Z",
        b"Mon, 7 Sep 2026 10:00:00 EST",
        b"Mon, 7 Sep 2026 10:00:00 EDT",
        b"Mon, 7 Sep 2026 10:00:00 PST",
        b"Mon, 7 Sep 2026 10:00:00 PDT",
        b"Mon, 7 Sep 2026 10:00:00 CST",
        b"Mon, 7 Sep 2026 10:00:00 MDT",
        b"Mon, 7 Sep 2026 10:00:00 AST",
        b"Mon, 7 Sep 2026 10:00:00 IST",
        b"Mon, 7 Sep 2026 10:00:00 -0000",
        b"Mon, 7 Sep 2026 10:00:00 +0000",
        b"Mon, 7 Sep 2026 10:00:00 -0800",
        b"Mon, 7 Sep 2026 10:00:00 +1400",
        b"Mon, 7 Sep 2026 10:00:00 -1200",
        b"Mon, 7 Sep 2026 10:00:00 +2359",
        b"Mon, 7 Sep 2026 10:00:00 +2400",
        b"Mon, 7 Sep 2026 10:00:00 +9999",
        b"Mon, 7 Sep 2026 10:00:00 +0570",
        b"Mon, 7 Sep 2026 10:00:00 +05:30",
        b"Mon, 7 Sep 2026 10:00:00 0530",
        b"Mon, 7 Sep 2026 10:00:00 530",
        b"Mon, 7 Sep 2026 10:00:00",
        b"Mon, 7 Sep 2026 10:00:00+0530",
        b"Mon, 7 Sep 2026 10:00:00-0800",
        b"Mon, 7 Sep 2026 10.00.00 +0530",
        b"Mon, 7 Sep 2026 10.00 +0530",
        b"Mon, 7 Sep 2026 1000 +0530",
        b"Mon, 7 Sep 26 10:00:00 +0530",
        b"Mon, 7 Sep 68 10:00:00 +0530",
        b"Mon, 7 Sep 69 10:00:00 +0530",
        b"Mon, 7 Sep 99 10:00:00 +0530",
        b"Mon, 7 Sep 0 10:00:00 +0530",
        b"Mon, 7 Sep 126 10:00:00 +0530",
        b"Mon, 7 Sep 0001 10:00:00 +0000",
        b"Mon, 1 Jan 0001 00:00:00 +0100",
        b"Fri, 31 Dec 9999 23:59:59 -0100",
        b"Fri, 31 Dec 9999 23:59:59 +0000",
        b"Mon, 7 Sep 10000 10:00:00 +0530",
        b"Monday, 7 September 2026 10:00:00 +0530",
        b"Mon, 7 SEP 2026 10:00:00 +0530",
        b"Mon, 7 sept 2026 10:00:00 +0530",
        b"Mon, Sep 7 2026 10:00:00 +0530",
        b"Sep 7, 2026 10:00:00 +0530",
        b"Mon Sep  7 10:00:00 2026",
        b"Mon Sep  7 10:00:00 +0530 2026",
        b"Monday, 07-Sep-26 10:00:00 GMT",
        b"07-Sep-2026 10:00:00 +0530",
        b"2026-09-07T10:00:00+05:30",
        b"2026-09-07 10:00:00 +0530",
        b"7/9/2026 10:00:00",
        b"Mon, 31 Feb 2026 10:00:00 +0530",
        b"Sun, 29 Feb 2026 10:00:00 +0530",
        b"Tue, 29 Feb 2028 10:00:00 +0530",
        b"Mon, 0 Sep 2026 10:00:00 +0530",
        b"Mon, 32 Sep 2026 10:00:00 +0530",
        b"Mon, 7 Sep 2026 24:00:00 +0530",
        b"Mon, 7 Sep 2026 23:60:00 +0530",
        b"Mon, 7 Sep 2026 23:59:60 +0530",
        b"Mon, 7 Sep 2026 -1:00:00 +0530",
        b"Mon, 7 Sep 2026 10:00:00.123 +0530",
        b"Mon, 7 Sep 2026 10:00:00 +0530 extra words here",
        b"Mon,7 Sep 2026 10:00:00 +0530",
        b"Mon , 7 Sep 2026 10:00:00 +0530",
        b"Wed, 7 Sep 2026 10:00:00 +0530",
        b"Xyz, 7 Sep 2026 10:00:00 +0530",
        b"7 Sep 2026",
        b"Sep 2026",
        b"10:00:00",
        b"not a date",
        b"",
        b"   ",
        b",",
        b"Mon,",
        b"Mon, 7, Sep, 2026, 10:00:00, +0530",
        b"Mon, 7 Sep 2026, 10:00:00 +0530",
        b"Mon, 7 Sep, 2026 10:00:00 +0530",
        b"Mon, 1_0 Sep 2_026 1_0:0_0:0_0 +05_30",
        b"Mon, +7 Sep +2026 +10:+00:+00 +0530",
        b"Mon, \xd9\xa7 Sep \xd9\xa2\xd9\xa0\xd9\xa2\xd9\xa6 10:00:00 +0530",
        b"=?utf-8?Q?Mon,_7_Sep_2026_10:00:00_+0530?=",
        b"Mon, 7 Sep 2026 10:00:00 +0530\r\n (folded comment)",
        b"Mon,\r\n 7 Sep 2026\r\n 10:00:00\r\n +0530",
        b"Thu, 1 Jan 1970 00:00:00 +0000",
        b"Wed, 31 Dec 1969 23:59:59 +0000",
        b"Tue, 19 Jan 2038 03:14:08 +0000",
        b"Sat, 1 Jan 2000 00:00:00 +0000",
        b"Mon, 7 Sep 2026 10:00:00 --0530",
        b"Mon, 7 Sep 2026 10:00:00 +-0530",
        b"Mon, 7 Sep 2026 10:00:00 -0",
        b"Mon, 7 Sep 2026 10:00:00 +0",
        b"Mon, 7 Sep 2026 10:00:00 -00",
        b"Mon, 7 Sep 2026 10:00:00 gmt",
        b"Mon, 7 Sep 2026 10:00:00 pst",
        b"Mon, 99999999999999999999 Sep 2026 10:00:00 +0530",
        b"Mon, 7 Sep 99999999999999999999 10:00:00 +0530",
        b"Mon, 7 Sep 2026 10:00:00 +99999999999999999999",
    ]
    cases = []
    for index, date in enumerate(dates):
        cases.append((f"date_{index}", crlf(
            b"Date: " + date,
            b"Received: from a.example.com by b.example.com; " + date,
            b"Subject: dates",
            b"From: a@example.com",
            b"",
            b"body",
        )))
    return cases


def handcrafted() -> list[tuple[str, bytes]]:
    return header_cases() + encoded_word_cases() + parameter_cases() + encoding_cases() + multipart_cases() + address_cases() + date_cases()


ALPHABET = b"-=;\"':?*%<>()[]@,. \t\r\n\\/_+&#!0aZ" + bytes([0x0B, 0x0C, 0x00, 0xE9, 0xC3, 0xA9, 0xFF, 0xE2, 0x82, 0xB9])


def mutate(rng: random.Random, data: bytes) -> bytes:
    chars = bytearray(data)
    for _ in range(rng.randrange(1, 6)):
        action = rng.randrange(6)
        position = rng.randrange(len(chars) + 1)
        if action == 0:
            chars.insert(position, rng.choice(ALPHABET))
        elif action == 1 and chars:
            del chars[min(position, len(chars) - 1)]
        elif action == 2 and chars:
            chars[min(position, len(chars) - 1)] = rng.choice(ALPHABET)
        elif action == 3 and chars:
            end = min(len(chars), position + rng.randrange(1, 12))
            del chars[position:end]
        elif action == 4 and chars:
            start = rng.randrange(len(chars))
            chunk = chars[start:start + rng.randrange(1, 30)]
            chars[position:position] = chunk
        elif chars:
            chars = chars[:max(1, position)]
    return bytes(chars)


def fuzzed(rng: random.Random, sources: list[bytes], count: int, limit: int = 2500) -> list[tuple[str, bytes]]:
    pool = [data for data in sources if 0 < len(data) <= limit]
    return [(f"fuzz_{index}", mutate(rng, rng.choice(pool))) for index in range(count)]
