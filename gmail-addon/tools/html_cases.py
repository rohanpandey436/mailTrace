from __future__ import annotations

import random
from html.parser import HTMLParser
from typing import Any

HANDCRAFTED: tuple[str, ...] = (
    "",
    "plain text only",
    "<p>Hello &amp; world</p>",
    "<p>one</p><p>two</p>",
    "<div>a<br>b<br/>c<br />d</div>",
    "<a href=\"https://example.com/login\">Sign in</a>",
    "<a href='https://example.com/a?b=1&amp;c=2'>x</a>",
    "<a href=https://example.com/bare>bare</a>",
    "<A HREF=\"HTTP://EXAMPLE.COM/UP\">Upper</A>",
    "<a href=\"x\" title=\"a&quot;b\" data-x=1 disabled>t</a>",
    "<a href=\"https://a.example/\"<b>broken</b></a>",
    "<a href=\"https://unterminated.example/",
    "<a href=\"https://a.example/\">unclosed anchor",
    "<a href='one'><a href='two'>nested</a></a>",
    "<a\nhref=\"https://newline.example/\"\n>multi\nline</a>",
    "<a href = \"https://spaced.example/\" >spaced</a>",
    "<a href=\"\">empty</a>",
    "<a>no href</a>",
    "<a href>valueless</a>",
    "<area href=\"https://area.example/\" alt=\"map\">",
    "<form action=\"https://form.example/post\" method=post><input name=q></form>",
    "<form action=\" \"></form>",
    "<iframe src=\"https://frame.example/\"></iframe>after frame",
    "<iframe src=\"https://frame.example/\"><a href=\"https://inside.example/\">in</a></iframe>",
    "<script>if (a<b && c>d) { document.write('<a href=\"https://s.example/\">x</a>'); }</script>after",
    "<script>unterminated script <b>bold</b>",
    "<SCRIPT type=\"text/javascript\">x</SCRIPT>y",
    "<script>a</scriptx>b</script>c",
    "<script>a</script >b",
    "<style>p { color: red; } a > b {}</style>styled",
    "<style>unterminated",
    "<title>T &amp; t <b>x</b></title>body",
    "<textarea><b>not bold</b> &lt;</textarea>z",
    "<xmp><b>raw</b> &amp;</xmp>z",
    "<noembed><a href=x>n</a></noembed>z",
    "<noframes><a href=x>n</a></noframes>z",
    "<noscript><a href=\"https://ns.example/\">ns</a></noscript>z",
    "<plaintext><b>everything &amp; after</b>",
    "<head><title>t</title><style>s</style></head><body>b</body>",
    "<template><p>tpl</p></template>out",
    "<!-- comment -->visible",
    "<!-->abrupt",
    "<!--->abrupt2",
    "<!-- a --!> b",
    "<!-- unterminated comment <p>x</p>",
    "<!--a--b-->c",
    "<!---->d",
    "<!----!>e",
    "<![CDATA[ c < d ]]>after",
    "<![CDATA[ unterminated",
    "<!DOCTYPE html><p>doc</p>",
    "<!doctype html public \"x\">lower",
    "<!DOCTYPE unterminated",
    "<!ELEMENT bogus>text",
    "<!>text",
    "<! >text",
    "<?xml version=\"1.0\"?>pi",
    "<?php echo 1; ?>pi",
    "<? unterminated",
    "</>ignored",
    "</ p>bogus",
    "</3>bogus",
    "</p",
    "</",
    "<",
    "a < b",
    "a <3 b",
    "a << b >> c",
    "x <- y",
    "1 < 2 && 3 > 2",
    "<>empty",
    "< p>space",
    "<p",
    "<p ",
    "<p a",
    "<p a=",
    "<p a=\"",
    "<p a=\"b",
    "<p a=\"b\"",
    "<p/>",
    "<p/ >",
    "<p / >",
    "<p//>",
    "<a/b/c>slashes</a>",
    "<a =x>eq</a>",
    "<a \"x\">q</a>",
    "<a 'x'=y>q</a>",
    "<a x=\"1\"y=\"2\">adjacent</a>",
    "<a x='1'y='2'z=3>adjacent</a>",
    "<a x=y=z>eqs</a>",
    "<a x==y>eqs</a>",
    "<a x=\"a>b\">gt in value</a>",
    "<a x='a>b'>gt in value</a>",
    "<a x=a>b>bare gt</a>",
    "<a x=\"&amp;&lt;&#65;&#x42;&copy&copy;&nosuch;&amp=1&ampx\">entities</a>",
    "<a x=&amp;>bare entity</a>",
    "<img src=x/>",
    "<img src=\"x\"/>",
    "<img src=\"cid:logo\" alt=\"A &amp; B\">",
    "<br/ >",
    "<div class=\"a\"id=\"b\">",
    "<DIV CLASS=\"Upper\">Case</DIV>",
    "<p>&amp</p>",
    "<p>&#x41</p>",
    "<p>&#65</p>",
    "<p>&nosuch;</p>",
    "<p>&notit;</p>",
    "<p>&</p>",
    "<p>& </p>",
    "<p>&#</p>",
    "<p>&#x</p>",
    "trailing &",
    "trailing &a",
    "trailing &amp",
    "trailing &#6",
    "trailing &#x4",
    "trailing &amp; ok",
    "AT&T and R&D",
    "a&b;c",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#0;&#128512;&#x1F600;&#xD800;&#1114112;",
    "<p>tab\there</p>\r\n<p>crlf</p>\r<p>cr</p>",
    "<td>cell1</td><td>cell2</td><th>head</th>",
    "<ul><li>one</li><li>two</li></ul>",
    "<ol><li>one<li>two</ol>",
    "<table><tr><td>a</td></tr><tr><td>b</td></tr></table>",
    "<h1>H1</h1><h2>H2</h2><h6>H6</h6><h7>H7</h7>",
    "<blockquote>q</blockquote><pre>  pre  \n  text </pre><hr>",
    "<section><article><header>h</header><footer>f</footer></article></section>",
    "<dl><dt>t</dt><dd>d</dd></dl>",
    "<span>in</span>line <b>bold</b> <i>it</i>",
    "<p>non breaking space here and thin</p>".replace("non breaking", "non" + chr(0xA0) + "breaking").replace("and thin", "and" + chr(0x2009) + "thin"),
    "<p>" + chr(0x939) + chr(0x93F) + chr(0x902) + chr(0x926) + chr(0x940) + " " + chr(0x1F600) + "</p>",
    "<a href=\"https://" + chr(0x430) + "pple.example/\">cyrillic</a>",
    "<p>zero" + chr(0x200B) + "width" + chr(0xFEFF) + "bom</p>",
    "<p>form" + chr(0x0C) + "feed" + chr(0x0B) + "vtab" + chr(0x1C) + "fs" + chr(0x85) + "nel" + chr(0x2028) + "ls</p>",
    "<p>null" + chr(0) + "byte</p>",
    "<a href=\"https://a.example/\" \n\t\r\f >ws</a>",
    "<a\thref=\"https://tab.example/\">tab</a>",
    "<a\fhref=\"https://ff.example/\">ff</a>",
    "<a" + chr(0x0B) + "href=\"https://vt.example/\">vt</a>",
    "<a" + chr(0xA0) + "href=\"https://nbsp.example/\">nbsp</a>",
    "<p>Dear customer,</p>\n<p>Your account <b>will be suspended</b>.</p>\n<p><a href=\"http://sbi-kyc.example.top/verify\">https://www.onlinesbi.sbi/</a></p>",
    "<html><head><meta charset=\"utf-8\"><style>body{}</style></head><body><div><p>x</p></div></body></html>",
    "<p>unclosed <b>bold <i>italic</p> tail",
    "</p></div></span>only end tags",
    "<p></p ></p\n>",
    "</p attr=\"x\">end with attr",
    "</script>stray",
    "</a href=\"https://end.example/\">",
    "<a href=\"javascript:alert(1)\">js</a><a href=\"data:text/html;base64,PGI+\">data</a>",
    "<a href=\"mailto:a@b.example\">mail</a><a href=\"tel:+911234567890\">tel</a><a href=\"#top\">top</a>",
    "<a href=\"  https://padded.example/  \">  padded   text  </a>",
    "<a href=\"https://a.example/\">line1\n   line2\t\tline3</a>",
    "<a href=\"https://a.example/\"><img src=x></a>",
    "<a href=\"https://a.example/\"><script>hidden</script>shown</a>",
    "<a href=\"https://a.example/\"><style>hidden</style>shown</a>",
    "<svg><a href=\"https://svg.example/\">svg</a></svg>",
    "<math><mi>x</mi></math>",
    "<p>" + "very long " * 60 + "</p>",
    "<" + "a" * 300 + ">",
    "<p " + "x=1 " * 80 + ">many attrs</p>",
    "<p>&" + "a" * 40 + ";</p>",
    "text &" + "b" * 33,
    "text &" + "b" * 34,
    "text &" + "b" * 35,
    "x" * 40 + "& tail",
    "x" * 40 + "&tail",
)

ALPHABET = "<>&;\"'/= \n\t-!?[]#xX0aAbpP:."


class Recorder(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.events: list[list[Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.events.append(["s", tag, [[name, value] for name, value in attrs]])

    def handle_endtag(self, tag: str) -> None:
        self.events.append(["e", tag])

    def handle_data(self, data: str) -> None:
        self.events.append(["d", data])


def record(text: str) -> dict[str, Any]:
    recorder = Recorder()
    error = ""
    try:
        recorder.feed(text)
        recorder.close()
    except Exception as exc:
        error = type(exc).__name__
    return {"events": recorder.events, "error": error}


def mutate(rng: random.Random, text: str) -> str:
    chars = list(text)
    for _ in range(rng.randrange(1, 5)):
        action = rng.randrange(4)
        position = rng.randrange(len(chars) + 1)
        if action == 0:
            chars.insert(position, rng.choice(ALPHABET))
        elif action == 1 and chars:
            del chars[min(position, len(chars) - 1)]
        elif action == 2:
            chars = chars[:position]
        elif chars:
            end = min(len(chars), position + rng.randrange(1, 6))
            del chars[position:end]
    return "".join(chars)


def fragments(rng: random.Random, sources: list[str], count: int) -> list[str]:
    out: list[str] = []
    pool = [text for text in sources if text]
    for _ in range(count):
        base = rng.choice(pool)
        if len(base) > 300:
            start = rng.randrange(0, len(base) - 300)
            base = base[start:start + rng.randrange(40, 300)]
        out.append(mutate(rng, base))
    return out


def random_markup(rng: random.Random, count: int) -> list[str]:
    out: list[str] = []
    for _ in range(count):
        out.append("".join(rng.choice(ALPHABET) for _ in range(rng.randrange(1, 40))))
    return out
