"""
bac/comparator.py
세션별 응답 비교 → BAC 판정

판정 기준:
  guest가 200 + 로그인 키워드 없음           → BAC_SUSPECTED_LOW
  member가 admin URL에 200 + admin 키워드   → BAC_SUSPECTED_MEDIUM
  member 응답이 admin 응답과 유사 (85% 이상) → BAC_SUSPECTED_HIGH
  IDOR: id 변경 후 200 + 정상 구조          → IDOR_SUSPECTED
"""
from __future__ import annotations

import time
from typing import Optional

import requests

from findings import (
    bac_finding,
    BAC_SUSPECTED_LOW,
    BAC_SUSPECTED_MEDIUM,
    BAC_SUSPECTED_HIGH,
    IDOR_SUSPECTED,
    HIGH, MEDIUM, LOW,
)
from bac.session_manager import GUEST, MEMBER, ADMIN

# ── 판정 기준 상수 ────────────────────────────────────────────────────────────

# 응답이 이 키워드 중 하나라도 포함하면 "로그인된 상태" 로 간주
_LOGIN_KEYWORDS = [
    "로그아웃", "마이페이지", "내 정보", "logout", "mypage",
    "sign out", "signout", "mb_id", "회원정보",
]

# 응답에 이 키워드가 있으면 "로그인 요구 페이지" 로 간주
_LOGIN_REQUIRED_KEYWORDS = [
    "로그인", "login", "sign in", "signin",
    "회원가입", "로그인이 필요", "로그인 후", "please login",
]

# 관리자 페이지 특유 키워드
_ADMIN_KEYWORDS = [
    "관리자", "admin", "administrator", "관리페이지", "관리자 페이지",
    "회원 관리", "게시판 관리", "사이트 관리", "권한 관리",
    "접속자", "통계", "admins",
]

# 응답 유사도 임계값 (이 이상이면 "거의 같은 응답"으로 판정)
_SIMILARITY_THRESHOLD = 0.85

# HTTP 요청 타임아웃
_REQUEST_TIMEOUT = 10

# 요청 간 딜레이 (초)
_REQUEST_DELAY = 0.3


# ── 유틸 ─────────────────────────────────────────────────────────────────────

def _contains_any(text: str, keywords: list[str]) -> Optional[str]:
    """text에서 첫 번째로 매칭되는 키워드 반환. 없으면 None."""
    tl = text.lower()
    for kw in keywords:
        if kw.lower() in tl:
            return kw
    return None


def _response_similarity(body_a: str, body_b: str) -> float:
    """두 응답 본문의 길이 기반 유사도 (0.0 ~ 1.0)."""
    len_a, len_b = len(body_a), len(body_b)
    if max(len_a, len_b) == 0:
        return 1.0
    return min(len_a, len_b) / max(len_a, len_b)


def _fetch(session: requests.Session, url: str) -> Optional[dict]:
    """GET 요청 후 응답 정보 반환. 실패 시 None."""
    try:
        time.sleep(_REQUEST_DELAY)
        resp = session.get(url, timeout=_REQUEST_TIMEOUT, allow_redirects=True)
        return {
            "status":    resp.status_code,
            "body":      resp.text,
            "final_url": resp.url,
            "length":    len(resp.text),
        }
    except Exception as e:
        return {"error": str(e)}


def _is_redirect_to_login(result: dict, original_url: str) -> bool:
    """응답이 로그인 페이지로 리다이렉트됐는지 확인."""
    if "error" in result:
        return False
    final = result.get("final_url", "")
    body  = result.get("body", "")
    return (
        "login" in final.lower()
        or "signin" in final.lower()
        or _contains_any(body, _LOGIN_REQUIRED_KEYWORDS) is not None
    )


def _is_error_page(result: dict) -> bool:
    """403, 401, 404 등 접근 거부/없음 응답인지 확인."""
    if "error" in result:
        return True
    return result.get("status", 0) in (401, 403, 404, 302)


# ── 판정 함수들 ───────────────────────────────────────────────────────────────

def _judge_vertical(
    candidate: dict,
    results: dict[str, dict],
) -> list[dict]:
    """
    수직 권한 상승 판정.
    guest / member 가 admin 경로에 접근 가능한지 확인.
    """
    findings = []
    url      = candidate["url"]
    category = candidate.get("category", "admin_path")

    # ── guest 판정 ──────────────────────────────────────────────────
    guest_result = results.get(GUEST)
    if guest_result and not _is_redirect_to_login(guest_result, url) and not _is_error_page(guest_result):
        body    = guest_result.get("body", "")
        status  = guest_result.get("status", 0)
        login_kw = _contains_any(body, _LOGIN_REQUIRED_KEYWORDS)
        admin_kw = _contains_any(body, _ADMIN_KEYWORDS)

        if status == 200 and not login_kw:
            confidence = HIGH if admin_kw else MEDIUM
            bac_type   = BAC_SUSPECTED_HIGH if admin_kw else BAC_SUSPECTED_LOW
            evidence   = (
                f"guest accessed {category} (status=200, "
                f"admin_keyword='{admin_kw or 'none'}', "
                f"login_redirect=false)"
            )
            print(f"[BAC] {bac_type}: {url} — {evidence}")
            findings.append(bac_finding(
                type=bac_type,
                category=category,
                url=url,
                status=status,
                evidence=evidence,
                confidence=confidence,
                extra={
                    "session": GUEST,
                    "expected_role": candidate.get("expected_role", "admin"),
                    "admin_keyword": admin_kw,
                },
            ))

    # ── member 판정 ─────────────────────────────────────────────────
    member_result = results.get(MEMBER)
    admin_result  = results.get(ADMIN)

    if member_result and not _is_error_page(member_result):
        body     = member_result.get("body", "")
        status   = member_result.get("status", 0)
        admin_kw = _contains_any(body, _ADMIN_KEYWORDS)

        if status == 200 and admin_kw:
            # member가 admin 키워드 있는 페이지에 200 접근
            evidence = (
                f"member accessed admin path (status=200, "
                f"admin_keyword='{admin_kw}')"
            )

            # admin 응답과 비교해서 유사도 높으면 HIGH
            bac_type   = BAC_SUSPECTED_MEDIUM
            confidence = MEDIUM

            if admin_result and not _is_error_page(admin_result):
                sim = _response_similarity(body, admin_result.get("body", ""))
                if sim >= _SIMILARITY_THRESHOLD:
                    bac_type   = BAC_SUSPECTED_HIGH
                    confidence = HIGH
                    evidence  += f", similarity_to_admin={sim:.1%}"

            print(f"[BAC] {bac_type}: {url} — {evidence}")
            findings.append(bac_finding(
                type=bac_type,
                category=category,
                url=url,
                status=status,
                evidence=evidence,
                confidence=confidence,
                extra={
                    "session": MEMBER,
                    "expected_role": candidate.get("expected_role", "admin"),
                    "admin_keyword": admin_kw,
                },
            ))

    return findings


def _judge_idor(
    candidate: dict,
    results: dict[str, dict],
) -> list[dict]:
    """
    IDOR 판정.
    guest 또는 member가 타인의 객체에 접근 가능한지 확인.
    """
    findings = []
    url      = candidate["url"]

    for level, result in results.items():
        if not result or _is_error_page(result):
            continue
        if _is_redirect_to_login(result, url):
            continue

        body   = result.get("body", "")
        status = result.get("status", 0)

        if status != 200:
            continue

        # 로그인 요구 키워드 없고 200이면 IDOR 의심
        login_kw = _contains_any(body, _LOGIN_REQUIRED_KEYWORDS)
        if not login_kw and len(body.strip()) > 100:
            param    = candidate.get("idor_param", "id")
            test_val = candidate.get("test_params", {}).get(param, "?")
            evidence = (
                f"IDOR: {param}={test_val} returned 200 "
                f"without login requirement (session={level}, "
                f"body_len={len(body)})"
            )
            print(f"[BAC] {IDOR_SUSPECTED}: {url} — {evidence}")
            findings.append(bac_finding(
                type=IDOR_SUSPECTED,
                category="idor",
                url=url,
                status=status,
                evidence=evidence,
                confidence=MEDIUM,
                param=param,
                extra={
                    "session":     level,
                    "idor_param":  param,
                    "idor_value":  test_val,
                    "id_type":     candidate.get("idor_id_type", "integer"),
                },
            ))
            break  # 한 세션에서 탐지하면 중복 방지

    return findings


def _judge_auth(
    candidate: dict,
    results: dict[str, dict],
) -> list[dict]:
    """
    인증 필요 경로에 guest가 접근 가능한지 판정.
    """
    findings = []
    url      = candidate["url"]

    guest_result = results.get(GUEST)
    if not guest_result or _is_redirect_to_login(guest_result, url) or _is_error_page(guest_result):
        return findings

    body   = guest_result.get("body", "")
    status = guest_result.get("status", 0)

    if status == 200 and not _contains_any(body, _LOGIN_REQUIRED_KEYWORDS):
        evidence = (
            f"guest accessed auth-required path "
            f"(status=200, no login redirect, body_len={len(body)})"
        )
        print(f"[BAC] {BAC_SUSPECTED_LOW}: {url} — {evidence}")
        findings.append(bac_finding(
            type=BAC_SUSPECTED_LOW,
            category="auth_path",
            url=url,
            status=status,
            evidence=evidence,
            confidence=LOW,
            extra={
                "session":       GUEST,
                "expected_role": candidate.get("expected_role", "member"),
            },
        ))
    return findings


# ── 메인 비교 함수 ────────────────────────────────────────────────────────────

def compare(
    candidate: dict,
    sessions: dict[str, requests.Session],
) -> list[dict]:
    """
    단일 후보 URL을 세션별로 요청하고 BAC 판정.

    Args:
        candidate: candidate_extractor.extract_candidates() 반환 항목
        sessions:  {level: requests.Session} 딕셔너리

    Returns:
        findings list (없으면 빈 리스트)
    """
    url            = candidate["url"]
    cand_type      = candidate.get("type", "vertical")
    session_levels = candidate.get("session_levels", [GUEST])

    # 요청할 세션만 필터링
    active_sessions = {
        lvl: s for lvl, s in sessions.items()
        if lvl in session_levels
    }

    # 요청 실행
    results: dict[str, dict] = {}
    for level, session in active_sessions.items():
        results[level] = _fetch(session, url)

    # 판정
    if cand_type == "idor":
        return _judge_idor(candidate, results)
    elif cand_type == "vertical":
        return _judge_vertical(candidate, results)
    elif cand_type in ("sensitive", "auth"):
        return _judge_auth(candidate, results)
    else:
        # 기본: 수직 판정
        return _judge_vertical(candidate, results)


def compare_all(
    candidates: list[dict],
    sessions: dict[str, requests.Session],
    progress_callback=None,
    max_candidates: int = 200,
) -> list[dict]:
    """
    전체 후보 목록에 대해 비교 수행.

    Args:
        candidates:        extract_candidates() 결과
        sessions:          {level: Session}
        progress_callback: (done, total) → None
        max_candidates:    최대 테스트 후보 수 (score 상위부터)

    Returns:
        전체 findings 리스트
    """
    targets = candidates[:max_candidates]
    total   = len(targets)
    all_findings: list[dict] = []
    found_urls: set[str] = set()

    print(f"[BAC] 비교 시작: {total}개 후보")

    for idx, candidate in enumerate(targets, start=1):
        if progress_callback:
            progress_callback(idx, total)

        findings = compare(candidate, sessions)

        for f in findings:
            key = (f.get("url"), f.get("type"))
            if key not in found_urls:
                found_urls.add(key)
                all_findings.append(f)

    print(f"[BAC] 비교 완료: findings={len(all_findings)}")
    return all_findings
