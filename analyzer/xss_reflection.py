from __future__ import annotations
import re
from enum import Enum
from urllib.parse import unquote


class ReflectionKind(Enum):
    RAW               = "raw"
    HTML_ENTITY       = "html_entity"
    URL_DECODED       = "url_decoded"
    HTML_THEN_URL     = "html_then_url"
    CASE_FOLDED       = "case_folded"
    NONE              = "none"


_ENTITY_RE = re.compile(r"&#([xX][0-9a-fA-F]{2,8}|[0-9]{2,8});")
_NAMED_ENTITY_RE = re.compile(r"(?i)&(lt|gt|amp|quot|apos);")

_NAMED_MAP = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}

# 완전 entity 인코딩 여부 판단용 — 구조 문자
_STRUCTURAL_CHARS = set('<>"\' ')


def decode_html_entities(s: str) -> str:
    def replace_num(m: re.Match) -> str:
        entity = m.group(1)
        try:
            cp = int(entity[1:], 16) if entity[0].lower() == "x" else int(entity)
            return chr(cp)
        except (ValueError, OverflowError):
            return m.group(0)

    out = _ENTITY_RE.sub(replace_num, s)
    out = _NAMED_ENTITY_RE.sub(lambda m: _NAMED_MAP.get(m.group(1).lower(), m.group(0)), out)
    return out


def _url_decode(s: str) -> str:
    try:
        decoded = unquote(s.replace("+", "%20"))
        return decoded if decoded != s else s
    except Exception:
        return s


def payload_variants(payload: str) -> list[str]:
    seen: list[str] = []
    seen.append(payload)

    html_dec = decode_html_entities(payload)
    if html_dec not in seen:
        seen.append(html_dec)

    for base in list(seen):
        cur = base
        for _ in range(4):
            url_dec = _url_decode(cur)
            if url_dec == cur:
                break
            if url_dec not in seen:
                seen.append(url_dec)
            cur = url_dec

    return seen


def payload_is_fully_entity_encoded(payload: str) -> bool:
    if any(c in payload for c in _STRUCTURAL_CHARS):
        return False
    decoded = decode_html_entities(payload)
    return decoded != payload and any(c in decoded for c in _STRUCTURAL_CHARS)


def payload_is_fully_url_encoded(payload: str) -> bool:
    if any(c in payload for c in _STRUCTURAL_CHARS):
        return False
    decoded = _url_decode(payload)
    return decoded != payload


# classify_reflection: 응답 body에서 payload가 어떻게 반사됐는지 분류
# Dalfox classify_reflection() 포트
def classify_reflection(body: str, payload: str) -> ReflectionKind:
    if not payload or not body:
        return ReflectionKind.NONE

    # 1. raw match
    if payload in body:
        if payload_is_fully_entity_encoded(payload):
            return ReflectionKind.NONE
        if payload_is_fully_url_encoded(payload):
            return ReflectionKind.NONE
        return ReflectionKind.RAW

    variants = payload_variants(payload)

    # 2. variant가 body에 있으면 URL decoded 반사
    for v in variants[1:]:
        if v in body:
            return ReflectionKind.URL_DECODED

    # 3. body를 html decode 후 payload variant 검색
    body_decoded = decode_html_entities(body)
    if body_decoded != body:
        for v in variants:
            if v in body_decoded:
                return ReflectionKind.HTML_ENTITY

    # 4. body를 url decode 후 검색
    body_url_dec = _url_decode(body)
    if body_url_dec != body:
        body_html_url = decode_html_entities(body_url_dec)
        for v in variants:
            if v in body_url_dec or v in body_html_url:
                return ReflectionKind.HTML_THEN_URL

    # 5. case folded (대소문자 변환 서버)
    body_lower = body.lower()
    for v in variants:
        if v.lower() in body_lower:
            return ReflectionKind.CASE_FOLDED

    return ReflectionKind.NONE
