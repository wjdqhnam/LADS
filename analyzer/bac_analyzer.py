"""
Broken Access Control (BAC) Analyzer
────────────────────────────────────
관리자 전용 경로에 비인가 계정으로 접근했는데
실제 관리자 페이지 콘텐츠가 노출되었는지 판정한다.

executor 출력(flat) / 기존 nested 형식 모두 입력 가능.
role 정보는 meta.role 또는 request_info.role 에서 추출.
"""
from __future__ import annotations

from typing import Optional

# 관리자 영역으로 간주하는 URL 조각
ADMIN_PATH_HINTS = (
    "/adm/",
    "/wp-admin",
    "/install/",
    "/admin/",
)

# 본문에서 "이건 로그인/접근거부 페이지다" 라는 신호
LOGIN_INDICATORS = (
    "login", "로그인", "auth",
    "접근 권한", "권한이 없", "unauthorized",
)

# 본문에서 "이건 진짜 관리자 페이지다" 라는 신호
ADMIN_INDICATORS = (
    "admin", "관리자", "회원관리",
    "설정", "dashboard", "환경설정",
)


# ── 입력 정규화 ──────────────────────────────────────────────────
def _extract(test_result: dict) -> dict:
    # nested (analyzer 기존 형식)
    if "request_info" in test_result or "response" in test_result:
        req  = test_result.get("request_info") or {}
        resp = test_result.get("response") or {}
        return {
            "url":    (req.get("url") or "").lower(),
            "role":   (req.get("role") or "guest").lower(),
            "status": resp.get("status"),
            "body":   (resp.get("body") or "").lower(),
        }

    # flat (executor 출력)
    meta = test_result.get("meta") or {}
    return {
        "url":    (test_result.get("url") or "").lower(),
        "role":   (meta.get("role") or test_result.get("role") or "guest").lower(),
        "status": test_result.get("status"),
        "body":   (test_result.get("response_body") or "").lower(),
    }


# ── 메인 진입점 ──────────────────────────────────────────────────
def validate_bac(test_result: dict) -> tuple[bool, str]:

    if not test_result:
        return False, "검증 불가 (입력 없음)"

    info = _extract(test_result)
    if not info["url"]:
        return False, "검증 불가 (URL 없음)"

    is_admin_path = any(hint in info["url"] for hint in ADMIN_PATH_HINTS)
    if not is_admin_path:
        return False, "안전함 (관리자 경로 아님)"

    if info["role"] == "admin":
        return False, "정상 (admin 계정 접근)"

    if info["status"] != 200:
        return False, f"안전함 (status={info['status']} — 차단됨)"

    body = info["body"]
    if any(ind in body for ind in LOGIN_INDICATORS):
        return False, "안전함 (로그인/접근거부 페이지로 라우팅)"

    if any(ind in body for ind in ADMIN_INDICATORS):
        return True, f"BAC 성공 (비인가 계정 '{info['role']}'으로 관리자 콘텐츠 노출)"

    return False, "안전함 (관리자 콘텐츠 시그니처 미검출)"