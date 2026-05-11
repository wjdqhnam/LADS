"""
bac/candidate_extractor.py
LLM BAC 응답 + 크롤 결과 → 테스트 후보 목록 생성 및 점수화

후보 dict 포맷:
{
  "url":             str,       # 테스트 대상 전체 URL
  "path":            str,       # 경로만 (쿼리스트링 포함 가능)
  "method":          "GET",
  "type":            str,       # vertical / horizontal / idor / sensitive
  "category":        str,       # admin_path / auth_path / idor / sensitive_path 등
  "priority":        int,       # LLM 판단 우선순위 (1-3)
  "score":           int,       # 점수화 결과 (높을수록 먼저 테스트)
  "description":     str,
  "required_params": dict,      # URL에 항상 필요한 파라미터
  "test_params":     dict,      # IDOR 테스트 시 실제 주입할 값
  "session_levels":  list[str], # 테스트할 세션 단계 ["guest"] or ["guest","member"] etc.
  "expected_role":   str,       # 정상적으로 접근 가능한 최소 권한
}
"""
from __future__ import annotations

import re
from urllib.parse import urlencode, urljoin, urlparse

# ── 점수화 기준 ───────────────────────────────────────────────────────────────

_HIGH_VALUE_PATH_KEYWORDS = [
    "admin", "manage", "management", "dashboard", "settings",
    "config", "configuration", "console", "panel", "control",
    "adm", "administrator", "superuser", "root",
]

_MEDIUM_VALUE_PATH_KEYWORDS = [
    "profile", "account", "user", "member", "mypage", "my_page",
    "private", "personal", "info", "detail", "view",
]

_IDOR_PARAM_KEYWORDS = [
    "id", "user_id", "uid", "mb_id", "wr_id", "post_id",
    "file_id", "no", "num", "idx", "seq", "order_id",
    "me_id", "bo_table", "gr_id", "msg_id", "comment_id",
]

# 자동 테스트 제외: 이 단어가 경로에 있으면 파괴적 액션 가능성
_EXCLUDE_PATH_KEYWORDS = [
    "delete", "remove", "drop", "truncate", "destroy",
    "del.php", "delete.php", "remove.php",
]

# IDOR 테스트 시 시도할 ID 값 목록
_IDOR_TEST_IDS = ["1", "2", "3", "100", "999"]


# ── 점수 계산 ─────────────────────────────────────────────────────────────────

def _score_path(path: str, priority: int = 1) -> int:
    score = priority  # LLM 우선순위 기본 점수
    pl = path.lower()

    for kw in _HIGH_VALUE_PATH_KEYWORDS:
        if kw in pl:
            score += 3
            break
    for kw in _MEDIUM_VALUE_PATH_KEYWORDS:
        if kw in pl:
            score += 2
            break

    return score


def _score_params(params: dict) -> int:
    score = 0
    for key in params:
        if any(kw in key.lower() for kw in _IDOR_PARAM_KEYWORDS):
            score += 2
            break
    return score


def _should_exclude(path: str, exclude_paths: list[str]) -> bool:
    pl = path.lower()
    # 명시적 제외 목록
    for ep in exclude_paths:
        if ep.rstrip("/") in path:
            return True
    # 파괴적 키워드 포함 여부
    for kw in _EXCLUDE_PATH_KEYWORDS:
        if kw in pl:
            return True
    return False


def _build_url(base_url: str, path: str, params: dict = None) -> str:
    base = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    url = base + path
    if params:
        url += "?" + urlencode(params)
    return url


def _crawled_path_set(crawled_urls: list[str]) -> set[str]:
    paths = set()
    for url in (crawled_urls or []):
        parsed = urlparse(url)
        paths.add(parsed.path.lower())
    return paths


# ── 후보 추출 함수들 ──────────────────────────────────────────────────────────

def _extract_admin_paths(
    bac_data: dict,
    base_url: str,
    exclude_paths: list[str],
    crawled_paths: set[str],
) -> list[dict]:
    candidates = []
    for item in bac_data.get("admin_paths", []):
        path = item.get("path", "")
        if not path or _should_exclude(path, exclude_paths):
            continue

        priority = item.get("priority", 2)
        score = _score_path(path, priority)
        # 크롤러에서 발견된 경로면 +2 (실제 존재 확인됨)
        if path.lower() in crawled_paths:
            score += 2

        candidates.append({
            "url":             _build_url(base_url, path, item.get("required_params")),
            "path":            path,
            "method":          "GET",
            "type":            "vertical",
            "category":        "admin_path",
            "priority":        priority,
            "score":           score,
            "description":     item.get("description", "Admin-only path"),
            "required_params": item.get("required_params") or {},
            "test_params":     {},
            "session_levels":  ["guest", "member"],
            "expected_role":   "admin",
        })
    return candidates


def _extract_auth_paths(
    bac_data: dict,
    base_url: str,
    exclude_paths: list[str],
    crawled_paths: set[str],
) -> list[dict]:
    candidates = []
    for item in bac_data.get("auth_paths", []):
        path = item.get("path", "")
        if not path or _should_exclude(path, exclude_paths):
            continue

        priority = item.get("priority", 1)
        score = _score_path(path, priority)
        if path.lower() in crawled_paths:
            score += 2

        candidates.append({
            "url":             _build_url(base_url, path, item.get("required_params")),
            "path":            path,
            "method":          "GET",
            "type":            "vertical",
            "category":        "auth_path",
            "priority":        priority,
            "score":           score,
            "description":     item.get("description", "Authenticated-only path"),
            "required_params": item.get("required_params") or {},
            "test_params":     {},
            "session_levels":  ["guest"],
            "expected_role":   "member",
        })
    return candidates


def _extract_idor_candidates(
    bac_data: dict,
    base_url: str,
    exclude_paths: list[str],
) -> list[dict]:
    candidates = []
    for item in bac_data.get("idor_params", []):
        param  = item.get("param", "")
        if not param:
            continue

        endpoints = item.get("likely_endpoints", [])
        priority  = item.get("priority", 2)

        for endpoint in endpoints:
            if _should_exclude(endpoint, exclude_paths):
                continue

            for test_id in _IDOR_TEST_IDS:
                test_params = {param: test_id}
                score = _score_path(endpoint, priority) + _score_params(test_params)

                candidates.append({
                    "url":             _build_url(base_url, endpoint, test_params),
                    "path":            endpoint,
                    "method":          "GET",
                    "type":            "horizontal",
                    "category":        "idor",
                    "priority":        priority,
                    "score":           score,
                    "description":     f"IDOR: {item.get('description','')} ({param}={test_id})",
                    "required_params": {},
                    "test_params":     test_params,
                    "session_levels":  ["guest", "member"],
                    "expected_role":   "owner",
                    "idor_param":      param,
                    "idor_id_type":    item.get("id_type", "integer"),
                })
    return candidates


def _extract_sensitive_paths(
    bac_data: dict,
    base_url: str,
    exclude_paths: list[str],
    crawled_paths: set[str],
) -> list[dict]:
    candidates = []
    for item in bac_data.get("sensitive_paths", []):
        path = item.get("path", "")
        if not path or _should_exclude(path, exclude_paths):
            continue

        priority = item.get("priority", 2)
        score = _score_path(path, priority)
        if path.lower() in crawled_paths:
            score += 2

        candidates.append({
            "url":             _build_url(base_url, path),
            "path":            path,
            "method":          "GET",
            "type":            "sensitive",
            "category":        "sensitive_path",
            "priority":        priority,
            "score":           score,
            "description":     f"Sensitive data: {item.get('description','')} ({item.get('data_type','')})",
            "required_params": {},
            "test_params":     {},
            "session_levels":  ["guest", "member"],
            "expected_role":   item.get("expected_role", "member"),
        })
    return candidates


def _extract_vertical_scenarios(
    bac_data: dict,
    base_url: str,
    exclude_paths: list[str],
) -> list[dict]:
    candidates = []
    for item in bac_data.get("vertical_escalation_scenarios", []):
        path = item.get("url", "")
        if not path or _should_exclude(path, exclude_paths):
            continue

        priority = item.get("priority", 2)
        session  = item.get("session_level", "guest")
        score    = _score_path(path, priority)

        candidates.append({
            "url":             _build_url(base_url, path),
            "path":            path,
            "method":          "GET",
            "type":            "vertical",
            "category":        "escalation_scenario",
            "priority":        priority,
            "score":           score,
            "description":     item.get("description", "Vertical escalation scenario"),
            "required_params": {},
            "test_params":     {},
            "session_levels":  [session],
            "expected_role":   "admin",
        })
    return candidates


def _extract_crawled_candidates(
    crawled_urls: list[str],
    base_url: str,
    exclude_paths: list[str],
    existing_paths: set[str],
) -> list[dict]:
    """
    크롤러가 발견했지만 LLM이 언급하지 않은 URL 중
    고가치 키워드 포함 경로를 추가로 후보에 올림.
    """
    candidates = []
    for url in (crawled_urls or []):
        parsed = urlparse(url)
        path   = parsed.path
        if path.lower() in existing_paths:
            continue
        if _should_exclude(path, exclude_paths):
            continue

        score = _score_path(path, priority=1)
        if score <= 1:  # 키워드 없으면 추가 안 함
            continue

        candidates.append({
            "url":             url,
            "path":            path,
            "method":          "GET",
            "type":            "vertical",
            "category":        "crawled_high_value",
            "priority":        1,
            "score":           score,
            "description":     f"High-value path found by crawler: {path}",
            "required_params": {},
            "test_params":     {},
            "session_levels":  ["guest", "member"],
            "expected_role":   "member",
        })
    return candidates


# ── 메인 추출 함수 ────────────────────────────────────────────────────────────

def extract_candidates(
    bac_data: dict,
    base_url: str,
    crawled_urls: list[str] = None,
) -> list[dict]:
    """
    LLM BAC 응답과 크롤 결과를 합쳐 테스트 후보 목록 생성.

    Args:
        bac_data:     parse_bac_response() 결과 dict
        base_url:     타깃 기본 URL
        crawled_urls: 크롤러가 발견한 URL 목록

    Returns:
        score 내림차순으로 정렬된 candidate dict 리스트
    """
    base_url     = base_url.rstrip("/")
    crawled_urls = crawled_urls or []
    exclude_paths = bac_data.get("exclude_paths", [])
    crawled_paths = _crawled_path_set(crawled_urls)

    all_candidates: list[dict] = []

    all_candidates += _extract_admin_paths(bac_data, base_url, exclude_paths, crawled_paths)
    all_candidates += _extract_auth_paths(bac_data, base_url, exclude_paths, crawled_paths)
    all_candidates += _extract_idor_candidates(bac_data, base_url, exclude_paths)
    all_candidates += _extract_sensitive_paths(bac_data, base_url, exclude_paths, crawled_paths)
    all_candidates += _extract_vertical_scenarios(bac_data, base_url, exclude_paths)

    # 크롤러 발견 URL 중 고가치 경로 추가
    existing = {c["path"].lower() for c in all_candidates}
    all_candidates += _extract_crawled_candidates(crawled_urls, base_url, exclude_paths, existing)

    # URL 기준 중복 제거
    seen: set[str] = set()
    deduped = []
    for c in all_candidates:
        if c["url"] not in seen:
            seen.add(c["url"])
            deduped.append(c)

    # 점수 내림차순 정렬
    deduped.sort(key=lambda c: (c["score"], c["priority"]), reverse=True)

    print(f"[BAC] 후보 추출 완료: {len(deduped)}개 (admin={sum(1 for c in deduped if c['category']=='admin_path')}, "
          f"auth={sum(1 for c in deduped if c['category']=='auth_path')}, "
          f"idor={sum(1 for c in deduped if c['category']=='idor')}, "
          f"sensitive={sum(1 for c in deduped if c['category']=='sensitive_path')})")
    return deduped
