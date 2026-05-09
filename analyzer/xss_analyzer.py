"""
XSS Analyzer
────────────
executor.py 출력(flat)과 기존 nested 형식을 모두 받아 XSS 여부를 판정한다.

판정 우선순위:
    1) HTML 인코딩 가드 — 페이로드가 인코딩된 형태로만 보이면 안전 처리
    2) 위험 마커 매칭   — 응답에 실행 가능한 XSS 시그니처가 인코딩 없이 노출
    3) 페이로드 반사    — 페이로드 자체가 본문에 그대로 반사

scanner.XSS_MARKERS / validator._XSS_MARKERS 와 동기화되어 있다.
"""
from __future__ import annotations

from typing import Optional

# ── 위험 마커 (scanner.XSS_MARKERS 와 동기화) ─────────────────────
# 응답에 인코딩 없이 이 문자열이 나타나면 XSS 가능성이 높다.
XSS_MARKERS = (
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
    "onerror=prompt",
    # 백틱 변형
    "onerror=alert`",
    "onmouseover=alert`",
)

# 인코딩 흔적 — 마커 주변에 보이면 안전한 것으로 간주
_ENCODED_TOKENS = ("&lt;", "&gt;", "&quot;", "&#x3c;", "&#60;", "&#x3e;", "&#62;")


# ── 입력 정규화 ──────────────────────────────────────────────────
def _extract_body(test_result: dict) -> str:
    """executor flat / nested 어느 형식이든 본문 문자열을 꺼낸다."""
    if "response" in test_result and isinstance(test_result["response"], dict):
        return test_result["response"].get("body") or ""
    return test_result.get("response_body") or ""


# ── 헬퍼 ─────────────────────────────────────────────────────────
def _is_encoded(body: str, idx: int, marker_len: int, window: int = 10) -> bool:
    """마커 주변 ±window 문자에 HTML 인코딩 토큰이 있는지 확인."""
    start = max(0, idx - window)
    end   = idx + marker_len + window
    surrounding = body[start:end]
    return any(tok in surrounding for tok in _ENCODED_TOKENS)


def _check_markers(body_lower: str, body_raw: str) -> Optional[str]:
    """위험 마커가 인코딩 없이 본문에 노출되어 있는지 확인."""
    for marker in XSS_MARKERS:
        idx = body_lower.find(marker)
        if idx == -1:
            continue
        if _is_encoded(body_raw, idx, len(marker)):
            continue
        return f"위험 마커 노출 ('{marker}')"
    return None


def _check_payload_reflection(payload: str, body_lower: str) -> Optional[str]:
    """페이로드 자체가 본문에 그대로 반사되었는지 확인."""
    if not payload:
        return None
    pl = payload.lower().strip()
    if len(pl) < 4:                     # 너무 짧은 문자열은 우연 매치 가능
        return None
    if pl in body_lower:
        return f"페이로드 반사 (payload 본문 내 그대로 노출)"
    return None


# ── 메인 진입점 ──────────────────────────────────────────────────
def validate_xss(test_result: dict) -> tuple[bool, str]:

    if not test_result:
        return False, "검증 불가 (입력 없음)"

    body_raw = _extract_body(test_result)
    if not body_raw:
        return False, "검증 불가 (응답 본문 없음)"

    body_lower = body_raw.lower()
    payload    = (test_result.get("payload") or "")
    context    = test_result.get("xss_context") or "unknown"

    # 1) 위험 마커 — 인코딩 가드 포함
    msg = _check_markers(body_lower, body_raw)
    if msg:
        return True, f"XSS 성공 [{context}] {msg}"

    # 2) 페이로드 반사 — 마커에 안 잡힌 변형 페이로드 보완
    msg = _check_payload_reflection(payload, body_lower)
    if msg:
        return True, f"XSS 성공 [{context}] {msg}"

    return False, "안전함 (XSS 시그니처 미검출 / 인코딩됨)"