"""
misconfig/checker.py
GET/HEAD 요청 → 룰 기반 검증 → findings 저장

체크 항목:
  - 민감 파일: .env, .git/config, composer.json 등
  - 백업 파일: config.php.bak, index.php.bak 등
  - 디렉토리 리스팅: /data/, /uploads/, /theme/ 등
  - phpinfo: phpinfo.php, info.php 등
  - 에러 노출: Fatal error, SQL syntax 등
  - 보안 헤더 누락: X-Frame-Options, CSP 등
  - 버전 정보 노출: Server, X-Powered-By 헤더
"""
from __future__ import annotations

import re
from typing import Optional

import requests

from findings import (
    misconfig_finding,
    append_findings,
    MISCONFIG_CONFIRMED,
    MISCONFIG_WARNING,
    HIGH,
    MEDIUM,
    LOW,
)

# ── 체크 대상: (경로, 카테고리, 룰 키) ──────────────────────────
_SENSITIVE_FILES: list[tuple[str, str, str]] = [
    ("/.env",               "sensitive_file", "env_exposure"),
    ("/.env.local",         "sensitive_file", "env_exposure"),
    ("/.env.production",    "sensitive_file", "env_exposure"),
    ("/.git/config",        "sensitive_file", "git_exposure"),
    ("/composer.json",      "sensitive_file", "composer_exposure"),
    ("/composer.lock",      "sensitive_file", "composer_exposure"),
    ("/config.php.bak",     "backup_file",    "backup_exposure"),
    ("/index.php.bak",      "backup_file",    "backup_exposure"),
    ("/wp-config.php.bak",  "backup_file",    "backup_exposure"),
    ("/db.php.bak",         "backup_file",    "backup_exposure"),
    ("/phpinfo.php",        "phpinfo",        "phpinfo_exposure"),
    ("/info.php",           "phpinfo",        "phpinfo_exposure"),
    ("/test.php",           "phpinfo",        "phpinfo_exposure"),
    ("/php_info.php",       "phpinfo",        "phpinfo_exposure"),
]

_DIRECTORY_PATHS: list[str] = [
    "/data/",
    "/uploads/",
    "/theme/",
    "/backup/",
    "/bbs/data/",
    "/bbs/upload/",
    "/files/",
    "/static/",
]

# ── 판정 룰: 키워드 매치 기준 ────────────────────────────────────
_RULES: dict[str, dict] = {
    "env_exposure": {
        "keywords": [
            "DB_PASSWORD", "DATABASE_PASSWORD", "SECRET_KEY", "APP_SECRET",
            "APP_KEY", "DATABASE_URL", "DB_HOST", "API_KEY", "AWS_SECRET",
            "MAIL_PASSWORD", "REDIS_PASSWORD",
        ],
        "evidence_prefix": "sensitive env variable found",
    },
    "git_exposure": {
        "keywords": ["[core]", "repositoryformatversion", "[remote", "filemode ="],
        "evidence_prefix": "git config keyword found",
    },
    "composer_exposure": {
        "keywords": ['"require"', '"name"', '"version"', '"autoload"'],
        "evidence_prefix": "composer manifest exposed",
    },
    "backup_exposure": {
        "keywords": ["<?php", "define(", "DB_", "password", "secret", "database"],
        "evidence_prefix": "backup file contains sensitive content",
    },
    "phpinfo_exposure": {
        "keywords": ["PHP Version", "phpinfo()", "PHP Extension", "php.ini Path", "PHP Credits"],
        "evidence_prefix": "phpinfo page exposed",
    },
    "directory_listing": {
        "keywords": ["Index of /", "Directory listing for", "Parent Directory", "<title>Index of"],
        "evidence_prefix": "directory listing enabled",
    },
}

# ── 보안 헤더: (헤더명, 카테고리) ───────────────────────────────
_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("X-Frame-Options",           "clickjacking_protection"),
    ("X-Content-Type-Options",    "mime_sniffing_protection"),
    ("Content-Security-Policy",   "csp"),
    ("Strict-Transport-Security", "hsts"),
    ("X-XSS-Protection",          "xss_header"),
    ("Referrer-Policy",           "referrer_policy"),
]

# 버전 정보를 노출하는 헤더
_VERSION_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
    "X-Drupal-Cache",
]

# 에러 노출 탐지 패턴
_ERROR_PATTERN = re.compile(
    r"(Fatal\s+error|Parse\s+error|SQL\s+syntax|mysql_fetch|mysqli_|"
    r"ORA-\d{5}|Microsoft\s+OLE\s+DB|ODBC\s+SQL|PostgreSQL.*ERROR|"
    r"Warning:\s+\w+\s*\(\)|Traceback\s+\(most\s+recent\s+call\s+last\))",
    re.IGNORECASE,
)

_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


# ── HTTP 헬퍼 ─────────────────────────────────────────────────

def _get(url: str, timeout: int = 10) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=False,
            headers=_REQUEST_HEADERS,
        )
    except Exception:
        return None


def _head(url: str, timeout: int = 10) -> Optional[requests.Response]:
    try:
        return requests.head(
            url, timeout=timeout, allow_redirects=False,
            headers=_REQUEST_HEADERS,
        )
    except Exception:
        return None


# ── 룰 매처 ──────────────────────────────────────────────────

def _match_keywords(body: str, rule_key: str) -> tuple[bool, str]:
    """body에서 rule_key에 해당하는 키워드 매치 여부와 evidence 반환."""
    rule = _RULES.get(rule_key)
    if not rule:
        return False, ""
    bl = body.lower()
    for kw in rule["keywords"]:
        if kw.lower() in bl:
            return True, f"{rule['evidence_prefix']}: '{kw}'"
    return False, ""


# ── 체크 함수들 ───────────────────────────────────────────────

def _check_sensitive_files(base_url: str) -> list[dict]:
    findings = []
    for path, category, rule_key in _SENSITIVE_FILES:
        url = base_url + path
        resp = _get(url)
        if resp is None or resp.status_code != 200:
            continue

        found, evidence = _match_keywords(resp.text, rule_key)
        if found:
            print(f"[MISCONFIG] CONFIRMED {category}: {url}")
            findings.append(misconfig_finding(
                type=MISCONFIG_CONFIRMED,
                category=category,
                url=url,
                status=resp.status_code,
                confidence=HIGH,
                evidence=evidence,
            ))
        else:
            # 200 응답이지만 키워드 없음 — 파일 존재 가능성 LOW 경고
            body_stripped = resp.text.strip()
            if body_stripped and len(body_stripped) > 20:
                print(f"[MISCONFIG] WARNING {category} (200, no keyword): {url}")
                findings.append(misconfig_finding(
                    type=MISCONFIG_WARNING,
                    category=category,
                    url=url,
                    status=resp.status_code,
                    confidence=LOW,
                    evidence=f"{path} returned HTTP 200 (no sensitive keywords matched — manual review recommended)",
                ))
    return findings


def _check_directory_listing(base_url: str) -> list[dict]:
    findings = []
    for path in _DIRECTORY_PATHS:
        url = base_url + path
        resp = _get(url)
        if resp is None or resp.status_code != 200:
            continue

        found, evidence = _match_keywords(resp.text, "directory_listing")
        if found:
            print(f"[MISCONFIG] CONFIRMED directory_listing: {url}")
            findings.append(misconfig_finding(
                type=MISCONFIG_CONFIRMED,
                category="directory_listing",
                url=url,
                status=resp.status_code,
                confidence=HIGH,
                evidence=evidence,
            ))
    return findings


def _check_security_headers(base_url: str) -> list[dict]:
    """홈페이지 대상 보안 헤더 누락 + 버전 노출 체크."""
    findings = []
    home_url = base_url + "/"

    resp = _head(home_url)
    if resp is None:
        resp = _get(home_url)
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # 보안 헤더 누락
    for header_name, category in _SECURITY_HEADERS:
        if header_name.lower() not in headers_lower:
            print(f"[MISCONFIG] WARNING missing_header: {header_name}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="missing_security_header",
                url=home_url,
                status=resp.status_code,
                confidence=MEDIUM,
                evidence=f"security header not set: {header_name}",
                extra={"header": header_name, "category": category},
            ))

    # 버전 정보 노출
    for header_name in _VERSION_HEADERS:
        value = headers_lower.get(header_name.lower())
        if value:
            print(f"[MISCONFIG] WARNING version_disclosure: {header_name}: {value}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="version_disclosure",
                url=home_url,
                status=resp.status_code,
                confidence=MEDIUM,
                evidence=f"version info exposed via header: {header_name}: {value}",
                extra={"header": header_name, "value": value},
            ))

    return findings


def _check_error_disclosure(base_url: str) -> list[dict]:
    """홈페이지에서 에러 메시지 노출 체크."""
    findings = []
    home_url = base_url + "/"

    resp = _get(home_url)
    if resp is None or not resp.text:
        return findings

    m = _ERROR_PATTERN.search(resp.text)
    if m:
        print(f"[MISCONFIG] CONFIRMED error_disclosure: {m.group(0)[:60]}")
        findings.append(misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="error_disclosure",
            url=home_url,
            status=resp.status_code,
            confidence=HIGH,
            evidence=f"error message in response: {m.group(0)[:100]}",
        ))

    return findings


# ── 메인 체크 함수 ────────────────────────────────────────────

def check(base_url: str, progress_callback=None) -> list[dict]:
    """
    base_url에 대해 전체 misconfiguration 체크 수행.

    Args:
        base_url: 타깃 기본 URL (예: http://example.com)
        progress_callback: (done, total) → None

    Returns:
        findings list (findings.py 포맷)
    """
    base_url = base_url.rstrip("/")
    findings: list[dict] = []

    steps = [
        ("민감 파일",        _check_sensitive_files),
        ("디렉토리 리스팅",  _check_directory_listing),
        ("보안 헤더",        _check_security_headers),
        ("에러 노출",        _check_error_disclosure),
    ]
    total = len(steps)

    for i, (label, fn) in enumerate(steps, start=1):
        print(f"[MISCONFIG] checking {label} ...")
        result = fn(base_url)
        findings.extend(result)
        if progress_callback:
            progress_callback(i, total)

    return findings


# ── run: 외부 진입점 ──────────────────────────────────────────

def run(
    base_url: str,
    output_file: str = "results/findings.json",
    progress_callback=None,
    append: bool = True,
) -> list[dict]:
    """
    misconfig 체크 후 findings 저장.

    Args:
        base_url:          타깃 기본 URL
        output_file:       저장 경로
        progress_callback: (done, total) → None
        append:            True면 기존 findings에 추가, False면 덮어쓰기

    Returns:
        이번 실행에서 발견된 findings list
    """
    import json
    import os

    print(f"[MISCONFIG] start → {base_url}")
    findings = check(base_url, progress_callback=progress_callback)

    confirmed = sum(1 for f in findings if f.get("type") == MISCONFIG_CONFIRMED)
    warnings  = sum(1 for f in findings if f.get("type") == MISCONFIG_WARNING)
    print(f"[MISCONFIG] done: confirmed={confirmed}, warning={warnings}, total={len(findings)}")

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    if append:
        append_findings(findings, output_file)
    else:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    result = run(target, output_file="results/misconfig_findings.json", append=False)
    print(f"\n총 {len(result)}개 발견")
    for f in result:
        print(f"  [{f['type']:22s}] [{f['confidence']:6s}] {f['category']:25s} {f['url']}")
        print(f"    → {f['evidence']}")
