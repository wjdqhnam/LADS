from __future__ import annotations

from typing import Any, Optional

# ── 공통 임계치 (scanner.py 와 동기화) ────────────────────────────
SLEEP_THRESHOLD = 4.5    # 초 — Time-based 판정 기준
BOOL_SIGNAL_MIN = 0.05   # Boolean 신호 최소 강도 (5%)

# ── DB 에러 시그니처 ──────────────────────────────────────────────
# scanner.MYSQL_ERRORS / validator._MYSQL_ERRORS 와 동일 (단일 진실원천 역할)
DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "column count doesn't match",
    "the used select statements have a different number",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "table 'g5_",   # Gnuboard5 테이블 노출 시그니처
)


# ── 입력 정규화 ──────────────────────────────────────────────────
def _extract_response(test_result: dict) -> dict:

    if "response" in test_result and isinstance(test_result["response"], dict):
        r = test_result["response"]
        return {
            "body":    (r.get("body") or "").lower(),
            "elapsed": float(r.get("elapsed") or 0.0),
            "length":  int(r.get("length") or 0),
            "status":  r.get("status"),
        }

    body = test_result.get("response_body") or ""
    return {
        "body":    body.lower(),
        "elapsed": float(test_result.get("elapsed") or 0.0),
        "length":  int(test_result.get("length") or 0),
        "status":  test_result.get("status"),
    }


# ── 개별 판정 함수 ────────────────────────────────────────────────
def _check_time_based(elapsed: float) -> Optional[str]:
    if elapsed >= SLEEP_THRESHOLD:
        return f"Time-based SQLi (응답 지연 {elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
    return None


def _check_error_based(body: str) -> Optional[str]:
    for sig in DB_ERROR_KEYWORDS:
        if sig in body:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


def _check_boolean_based(length: int, controls: dict) -> Optional[str]:

    true_len  = controls.get("true_len")
    false_len = controls.get("false_len")
    if true_len is None or false_len is None:
        return None

    span = abs(true_len - false_len)
    if span == 0:
        return None  # 컨트롤 그룹 차이가 없으면 Boolean 판정 불가

    dist_true  = abs(length - true_len)
    dist_false = abs(length - false_len)

    if dist_true >= dist_false:
        return None  # 참 쪽이 아니라 거짓 쪽에 더 가까움

    signal = (dist_false - dist_true) / max(span, 1)
    if signal >= BOOL_SIGNAL_MIN:
        return f"Boolean-based SQLi (signal {signal:.1%})"
    return None


# ── 메인 진입점 ──────────────────────────────────────────────────
def validate_sqli(test_result: dict) -> tuple[bool, str]:

    if not test_result:
        return False, "검증 불가 (입력 없음)"

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)"

    # 1) Time-based
    msg = _check_time_based(resp["elapsed"])
    if msg:
        return True, msg

    # 2) Error-based
    msg = _check_error_based(resp["body"])
    if msg:
        return True, msg

    # 3) Boolean-based (controls 가 있을 때만 동작 — 없으면 자연스럽게 skip)
    controls = test_result.get("controls") or {}
    msg = _check_boolean_based(resp["length"], controls)
    if msg:
        return True, msg

    return False, "안전함 (SQLi 시그니처 미검출)"