from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

SLEEP_THRESHOLD       = 4.5
BOOL_SIGNAL_MIN       = 0.05
BOOL_GROUP_THRESHOLD  = 0.05
ORDERBY_DIFF_THRES    = 0.10

UNION_ERROR_KEYWORDS = (
    "the used select statements have a different number",
    "column count doesn't match",
)

DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "table 'g5_",
)

# Boolean 분석 후보 (느슨하게)
_BOOL_TRUE = re.compile(
    r"1\s*=\s*1|'\s*([a-z0-9])\s*'\s*=\s*'\s*\1|\bor\s+1\b|\band\s+1\s*=\s*1|\btrue\b|length\(.+\)\s*>\s*0|exists\s*\(|case\s+when\s*\(\s*1\s*=\s*1",
    re.IGNORECASE,
)
_BOOL_FALSE = re.compile(
    r"1\s*=\s*2|1\s*=\s*0|\band\s+1\s*=\s*2|\bfalse\b|\band\s+0\b|case\s+when\s*\(\s*1\s*=\s*2",
    re.IGNORECASE,
)

# ORDER BY 패턴
_ORDERBY_INJECT = re.compile(r"order\s+by\s+(?:\d+|\(|\w+\s*,)", re.IGNORECASE)
_ORDERBY_NUM = re.compile(r"order\s+by\s+(\d+)", re.IGNORECASE)


def _is_group_candidate(payload: str) -> bool:
    """
    이 페이로드는 그룹 분석 대상인가?
    Boolean true/false 페어나 ORDER BY 페이로드는 단건 Error 판정을 보류하고
    그룹 분석에서 처리하도록 양보한다.
    """
    if not payload:
        return False
    if _BOOL_TRUE.search(payload):
        return True
    if _BOOL_FALSE.search(payload):
        return True
    if _ORDERBY_INJECT.search(payload):
        return True
    return False


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


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _body_length(r: dict) -> int:
    body = r.get("response_body") or ""
    return len(body)


def _check_time_based(elapsed: float) -> Optional[str]:
    if elapsed >= SLEEP_THRESHOLD:
        return f"Time-based SQLi (응답 지연 {elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
    return None


def _check_error_based(body: str) -> Optional[str]:
    for sig in UNION_ERROR_KEYWORDS:
        if sig in body:
            return f"UNION-based SQLi (컬럼 수 mismatch: '{sig[:50]}')"
    for sig in DB_ERROR_KEYWORDS:
        if sig in body:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


def validate_sqli(test_result: dict) -> tuple[bool, str]:
    """단건 판정 — 그룹 후보는 보류"""
    if not test_result:
        return False, "검증 불가 (입력 없음)"

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)"

    # Time-based는 그룹과 무관 → 우선 처리
    msg = _check_time_based(resp["elapsed"])
    if msg:
        return True, msg

    # 그룹 분석 후보 페이로드는 단건 Error 판정 보류
    # (이 환경에서는 그누보드처럼 모든 SQL에 같은 에러를 주므로,
    #  Boolean true/false나 ORDER BY는 그룹에서 응답 차이로 판정하는 게 정확)
    payload = test_result.get("payload") or ""
    if _is_group_candidate(payload):
        return False, "그룹 분석 대상 (Phase 2로 위임)"

    # 그룹 후보 아닌 페이로드만 Error 판정
    msg = _check_error_based(resp["body"])
    if msg:
        return True, msg

    return False, "안전함 (SQLi 시그니처 미검출)"


def detect_boolean_group(results: list[dict]) -> list[dict]:
    """그룹 단위 Boolean SQLi 판정"""
    sqli_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = (r.get("point"), r.get("inject_param"), r.get("url"), r.get("inject_mode"))
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        true_items, false_items = [], []
        for r in group:
            payload = r.get("payload") or ""
            if _BOOL_TRUE.search(payload):
                true_items.append(r)
            if _BOOL_FALSE.search(payload):
                false_items.append(r)

        if not true_items or not false_items:
            continue

        avg_true  = sum(_body_length(r) for r in true_items)  / len(true_items)
        avg_false = sum(_body_length(r) for r in false_items) / len(false_items)
        max_len   = max(avg_true, avg_false, 1)
        diff      = abs(avg_true - avg_false) / max_len

        if diff < BOOL_GROUP_THRESHOLD:
            continue

        direction = "true>false" if avg_true > avg_false else "true<false"
        evidence = (
            f"Boolean-based SQLi (group): true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
            f"diff={diff:.1%} ({direction})"
        )

        best = max(true_items, key=_body_length)
        detected.append({"result": best, "evidence": evidence})

    return detected


def detect_orderby_group(results: list[dict]) -> list[dict]:
    """그룹 단위 ORDER BY SQLi 판정"""
    orderby_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and _ORDERBY_INJECT.search(r.get("payload") or "")
    ]

    if not orderby_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in orderby_results:
        key = (r.get("point"), r.get("inject_param"), r.get("url"), r.get("inject_mode"))
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        if len(group) < 2:
            continue

        lengths = [_body_length(r) for r in group]
        min_len, max_len_v = min(lengths), max(lengths)
        if max_len_v == 0:
            continue

        diff = (max_len_v - min_len) / max_len_v

        has_error = any(
            "unknown column" in (r.get("response_body") or "").lower()
            for r in group
        )

        if diff < ORDERBY_DIFF_THRES and not has_error:
            continue

        evidence_extra = " + 'unknown column' 에러" if has_error else ""
        evidence = (
            f"ORDER BY SQLi (group): {len(group)}개 페이로드 응답 분산 "
            f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%}){evidence_extra}"
        )

        best = max(group, key=_body_length)
        detected.append({"result": best, "evidence": evidence})

    return detected