import os
import sys
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# 로그인 관련 환경 변수
LOGIN_URL = os.getenv("LOGIN_URL", "")
LOGIN_METHOD = os.getenv("LOGIN_METHOD", "POST").upper()
LOGIN_ID_1 = os.getenv("LOGIN_ID_1", "")
LOGIN_PASSWORD_1 = os.getenv("LOGIN_PASSWORD_1", "")
LOGIN_ID_2 = os.getenv("LOGIN_ID_2", "")
LOGIN_PASSWORD_2 = os.getenv("LOGIN_PASSWORD_2", "")
LOGIN_FAIL_INDICATOR = os.getenv("LOGIN_FAIL_INDICATOR", "")
ADMIN_ID = os.getenv("ADMIN_ID", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
_TIMEOUT = 10

# 인증상태 탐지용 힌트
AUTH_TEXT_HINTS = (
    "logout",
    "log out",
    "sign out",
    "my account",
    "my page",
    "profile",
    "dashboard",
)

# 로그인 링크 탐지용 힌트
LOGIN_LINK_HINTS = (
    "login",
    "log in",
    "log-in",
    "signin",
    "sign in",
    "sign-in",
)



@dataclass
class LoginAssessment: 
    # 로그인 시도 후 판정된 결과 담는 구조체. 외부 반환은 bool, cookies로 유지.
    status: str
    reason: str
    signals: dict = field(default_factory=dict)


def _make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
    })
    return session


def extract_hidden_inputs(form_tag) -> dict:
    hidden = {}
    if not form_tag:
        return hidden
    for inp in form_tag.find_all("input", {"type": "hidden"}):
        name = inp.get("name")
        if name:
            hidden[name] = inp.get("value", "")
    return hidden


# name/id/placeholder/autocomplete 속성으로 아이디, 비밀번호 필드 추론
def infer_login_fields(form_tag) -> Optional[tuple[str, str]]:
    if not form_tag:
        return None

    inputs = form_tag.find_all("input")

    # 비밀번호 필드 찾기
    password_name = ""

    for inp in inputs:
        name = inp.get("name", "")
        input_type = inp.get("type", "text").lower()
        haystack = " ".join([
            name,
            inp.get("id", ""),
            inp.get("placeholder", ""),
            inp.get("autocomplete", ""),
        ]).lower()
        if name and (input_type == "password" or any(t in haystack for t in ("pass", "passwd", "pw"))):
            password_name = name
            break

    # 아이디 필드 찾기 (점수 기반: 이메일/텍스트 타입)
    id_name = ""
    candidates = []
    for idx, inp in enumerate(inputs):
        name = inp.get("name", "")
        input_type = inp.get("type", "text").lower()
        if not name or name == password_name or input_type in {"hidden", "password", "submit", "button", "checkbox", "radio"}:
            continue
        haystack = " ".join([
            name,
            inp.get("id", ""),
            inp.get("placeholder", ""),
            inp.get("autocomplete", ""),
        ]).lower()
        score = 2 if input_type in {"text", "email", "tel"} else 0
        if any(token in haystack for token in ("login", "user", "userid", "username", "email", "member", "mb_id", "id")):
            score += 5
        candidates.append((score, -idx, name))

    if candidates:
        id_name = max(candidates)[2]

    if id_name and password_name:
        return id_name, password_name
    return None


# 페이지에서 로그인 폼 탐색 
def find_login_form(soup):
    for form in soup.find_all("form"):
        if infer_login_fields(form):
            return form
    return None


# 비로그인 사용자에게 보이는 로그인 링크 탐지
def _has_login_link(soup) -> bool:
    for link in soup.find_all("a", href=True):
        haystack = " ".join([
            str(link.get("href") or ""),
            link.get_text(" ", strip=True),
        ]).lower()
        if any(token in haystack for token in LOGIN_LINK_HINTS):
            return True
    return False


# 로그인 상태를 나타내는 범용 텍스트 힌트 탐지
def _has_auth_text(text: str) -> bool:
    haystack = text.lower()
    return any(token in haystack for token in AUTH_TEXT_HINTS)


def _check_login_state(
    session: requests.Session,
    check_url: str,
    fail_indicator: str,
    timeout: int,
) -> dict:
    # 로그인 후 페이지를 다시 요청해 DAST식 상태 신호 수집
    signals = {
        "check_requested": False,
        "check_url": check_url,
        "check_status_code": None,
        "check_login_form_present": None,
        "check_login_link_present": None,
        "check_auth_text_present": None,
        "check_fail_indicator_present": False,
        "check_error": "",
    }
    if not check_url:
        return signals

    try:
        resp = session.get(check_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        signals["check_error"] = str(exc)
        return signals

    soup = BeautifulSoup(resp.text, "lxml")
    signals.update({
        "check_requested": True,
        "check_url": resp.url,
        "check_status_code": resp.status_code,
        "check_login_form_present": bool(find_login_form(soup)),
        "check_login_link_present": _has_login_link(soup),
        "check_auth_text_present": _has_auth_text(resp.text),
        "check_fail_indicator_present": bool(fail_indicator and fail_indicator in resp.text.lower()),
    })
    return signals


# 로그인 시도 후 수집된 시도로 성공, 실패 판정
def _assess_login(signals: dict) -> LoginAssessment:
    if signals.get("fail_indicator_present"):
        return LoginAssessment("failed", "fail indicator present", signals)

    if signals.get("check_fail_indicator_present"):
        return LoginAssessment("failed", "fail indicator present on check URL", signals)

    if signals.get("post_login_form_present") and not signals.get("new_cookie_names"):
        return LoginAssessment("failed", "login form reappeared without new cookies", signals)

    check_confirms_login = (
        signals.get("check_requested")
        and not signals.get("check_login_form_present")
        and (
            signals.get("check_auth_text_present")
            or (
                signals.get("login_link_present_before")
                and not signals.get("check_login_link_present")
                and signals.get("new_cookie_names")
            )
        )
    )
    if check_confirms_login:
        return LoginAssessment("confirmed", "check URL shows authenticated state", signals)

    if not signals.get("post_login_form_present") and signals.get("new_cookie_names"):
        return LoginAssessment("probable", "login form disappeared and new cookies were set", signals)

    return LoginAssessment("unknown", "no clear success or failure evidence", signals)


# 범용 CMS 로그인 경로 사용해 로그인 URL 탐색
def _candidate_login_urls(base_url: str) -> list[str]:
    base = base_url.rstrip("/") + "/"
    paths = [
        "login",
        "login/",
        "login.php",
        "signin",
        "sign-in",
        "account/login",
        "user/login",
        "users/sign_in",
        "admin",
        "admin/login",
        "wp-login.php",
        "wp-admin/",
    ]
    return [urljoin(base, path) for path in paths]


def _login_hint_score(text: str) -> int:
    haystack = text.lower()
    score = 0
    for token in ("login", "log-in", "signin", "sign-in", "sign_in", "wp-login", "sign in", "log in"):
        if token in haystack:
            score += 4
    for token in ("account", "member", "user", "admin", "auth", "session"):
        if token in haystack:
            score += 1
    return score


# 링크와 공통 로그인 경로에서 실제 로그인 폼 탐색
def discover_login_url(base_url: str, timeout: int = _TIMEOUT) -> str:
    if not base_url:
        return ""

    session = _make_session()
    candidates: list[tuple[int, str]] = []

    try:
        resp = session.get(base_url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "lxml")

        for link in soup.find_all("a", href=True):
            href = str(link.get("href") or "")
            text = link.get_text(" ", strip=True)
            score = _login_hint_score(f"{href} {text}")
            if score:
                candidates.append((score + 2, urljoin(resp.url, href)))

        if find_login_form(soup):
            candidates.append((1, resp.url))
    except requests.RequestException:
        pass

    candidates.extend((1, url) for url in _candidate_login_urls(base_url))

    seen: set[str] = set()
    for _score, candidate in sorted(candidates, key=lambda item: item[0], reverse=True):
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            resp = session.get(candidate, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue
        if resp.status_code >= 400:
            continue
        soup = BeautifulSoup(resp.text, "lxml")
        if find_login_form(soup):
            return resp.url

    return ""


# env는 수정하지 않고 현재 프로세스에서만 LOGIN_URL 확정
def ensure_login_url(base_url: str, timeout: int = _TIMEOUT) -> str:
    global LOGIN_URL

    current = os.getenv("LOGIN_URL", "") or LOGIN_URL
    if current:
        return current

    discovered = discover_login_url(base_url, timeout=timeout)
    if not discovered:
        return ""

    LOGIN_URL = discovered
    os.environ["LOGIN_URL"] = discovered
    print(f"[AUTH] discovered LOGIN_URL: {discovered}")
    return discovered


def login(
    session: requests.Session,
    url: str = LOGIN_URL,
    method: str = LOGIN_METHOD,
    login_id: str = LOGIN_ID_1,
    login_password: str = LOGIN_PASSWORD_1,
    fail_indicator: str = LOGIN_FAIL_INDICATOR,
    base_url: str = "",
    timeout: int = _TIMEOUT,
) -> tuple[bool, dict]:

    # 로그인 수행, (성공 여부, 쿠키) 반환 — 실패 시 (False, {})
    if not url:
        return False, {}

    fail_indicator = fail_indicator.lower()

    try:
        get_resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[LOGIN] GET failed: {exc}", file=sys.stderr)
        return False, {}

    pre_cookies = set(session.cookies.get_dict().keys())
    soup = BeautifulSoup(get_resp.text, "lxml")
    form_tag = find_login_form(soup)
    login_link_present_before = _has_login_link(soup)

    if not form_tag:
        print("[LOGIN] login form not found", file=sys.stderr)
        return False, {}

    inferred = infer_login_fields(form_tag)
    if not inferred:
        print("[LOGIN] could not infer login fields", file=sys.stderr)
        return False, {}
    id_field, password_field = inferred

    payload = extract_hidden_inputs(form_tag)
    payload[id_field] = login_id
    payload[password_field] = login_password
    action = form_tag.get("action", "").strip()
    post_url = urljoin(get_resp.url, action) if action else get_resp.url

    try:
        if method == "GET":
            post_resp = session.get(post_url, params=payload, timeout=timeout, allow_redirects=True)
        else:
            post_resp = session.post(post_url, data=payload, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[LOGIN] request failed: {exc}", file=sys.stderr)
        return False, {}

    cookies = session.cookies.get_dict()
    new_cookies = set(cookies.keys()) - pre_cookies
    body_lower = post_resp.text.lower()
    post_soup = BeautifulSoup(post_resp.text, "lxml")
    form_reappeared = bool(find_login_form(post_soup))

    # 로그인 후 최종 URL, 없으면 사이트 기준 URL
    effective_check_url = post_resp.url or base_url
    check_signals = _check_login_state(session, effective_check_url, fail_indicator, timeout)

    signals = {
        "fail_indicator_present": bool(fail_indicator and fail_indicator in body_lower),
        "post_login_form_present": form_reappeared,
        "login_link_present_before": login_link_present_before,
        "new_cookie_names": sorted(new_cookies),
        "cookie_count": len(cookies),
    }
    signals.update(check_signals)

    assessment = _assess_login(signals)
    print(f"[LOGIN] status={assessment.status}: {assessment.reason}, cookies={len(cookies)}")

    if assessment.status in {"confirmed", "probable"}:
        return True, cookies

    if assessment.status == "failed":
        print(f"[LOGIN] failed: {assessment.reason}", file=sys.stderr)
    else:
        print(f"[LOGIN] unknown: {assessment.reason}", file=sys.stderr)
    return False, {}


# 역할별 세션 쿠키 반환
def login_all_roles(
    url: str = LOGIN_URL,
    method: str = LOGIN_METHOD,
    fail_indicator: str = LOGIN_FAIL_INDICATOR,
    base_url: str = "",
    timeout: int = _TIMEOUT,
) -> dict[str, dict]:
    
    roles: dict[str, dict] = {"guest": {}}
    url = url or os.getenv("LOGIN_URL", "") or ensure_login_url(base_url, timeout=timeout)
    if not url:
        print("[AUTH] login URL not configured and auto-discovery failed", file=sys.stderr)
        return roles

    common = dict(
        url=url,
        method=method,
        fail_indicator=fail_indicator,
        base_url=base_url,
        timeout=timeout,
    )

    if LOGIN_ID_1:
        session = _make_session()
        ok, cookies = login(session, login_id=LOGIN_ID_1, login_password=LOGIN_PASSWORD_1, **common)
        if ok:
            roles["member"] = cookies
            print(f"[AUTH - OK] member login success: {len(cookies)} cookies")
        else:
            print("[AUTH - FAIL] member login failed; skipped", file=sys.stderr)

    if LOGIN_ID_2:
        session = _make_session()
        ok, cookies = login(session, login_id=LOGIN_ID_2, login_password=LOGIN_PASSWORD_2, **common)
        if ok:
            roles["member2"] = cookies
            print(f"[AUTH - OK] member2 login success: {len(cookies)} cookies")
        else:
            print("[AUTH - FAIL] member2 login failed; skipped", file=sys.stderr)

    if ADMIN_ID:
        session = _make_session()
        ok, cookies = login(session, login_id=ADMIN_ID, login_password=ADMIN_PASSWORD, **common)
        if ok:
            roles["admin"] = cookies
            print(f"[AUTH - OK] admin login success: {len(cookies)} cookies")
        else:
            print("[AUTH - FAIL] admin login failed; skipped", file=sys.stderr)

    return roles
