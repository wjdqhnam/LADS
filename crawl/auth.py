import os
import sys
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# 로그인 관련 환경 변수
LOGIN_URL = os.getenv("LOGIN_URL", "")
LOGIN_METHOD = os.getenv("LOGIN_METHOD", "POST").upper()
LOGIN_ID = os.getenv("LOGIN_ID", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")
LOGIN_SUCCESS_URL_KEYWORD = os.getenv("LOGIN_SUCCESS_URL_KEYWORD", "")
LOGIN_FAIL_INDICATOR = os.getenv("LOGIN_FAIL_INDICATOR", "")

# BAC 멀티 세션용 관리자 계정
ADMIN_ID = os.getenv("ADMIN_ID", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
_TIMEOUT = 10


# CSRF 토큰 등 hidden input 값 추출
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
        haystack = " ".join([name, inp.get("id", ""), inp.get("placeholder", ""), inp.get("autocomplete", "")]).lower()
        if name and (input_type == "password" or "pass" in haystack or "passwd" in haystack or "pw" in haystack):
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
        haystack = " ".join([name, inp.get("id", ""), inp.get("placeholder", ""), inp.get("autocomplete", "")]).lower()
        score = 2 if input_type in {"text", "email", "tel"} else 0
        if any(token in haystack for token in ["login", "user", "userid", "username", "email", "member", "mb_id", "id"]):
            score += 5
        candidates.append((score, -idx, name))  # -idx: 점수 동일 시 앞쪽 필드 우선

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


def login(
    session: requests.Session,
    url: str = LOGIN_URL,
    method: str = LOGIN_METHOD,
    login_id: str = LOGIN_ID,    
    login_password: str = LOGIN_PASSWORD, 
    success_url_keyword: str = LOGIN_SUCCESS_URL_KEYWORD,
    fail_indicator: str = LOGIN_FAIL_INDICATOR,
    timeout: int = _TIMEOUT,
) -> tuple[bool, dict]:

    # 로그인 수행, (성공 여부, 쿠키) 반환 — 실패 시 (False, {})
    if not url:
        return False, {}

    success_url_keyword = success_url_keyword.lower()
    fail_indicator = fail_indicator.lower()

    try:
        get_resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[LOGIN] GET failed: {exc}", file=sys.stderr)
        return False, {}

    pre_cookies = set(session.cookies.get_dict().keys())

    soup = BeautifulSoup(get_resp.text, "lxml")
    form_tag = find_login_form(soup)

    if not form_tag:
        print("[LOGIN] login form not found", file=sys.stderr)
        return False, {}

    inferred = infer_login_fields(form_tag)
    if not inferred:
        print("[LOGIN] could not infer login fields", file=sys.stderr)
        return False, {}
    id_field, password_field = inferred

    # hidden 필드 포함해 페이로드 구성
    payload = extract_hidden_inputs(form_tag)
    payload[id_field] = login_id
    payload[password_field] = login_password
    action = form_tag.get("action", "").strip()
    post_url = urljoin(url, action) if action else url

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
    final_url_lower = post_resp.url.lower()

    post_soup = BeautifulSoup(post_resp.text, "lxml")
    form_reappeared = bool(find_login_form(post_soup))
    url_changed = post_resp.url.rstrip("/") != url.rstrip("/")

    # 1) 사용자 지정 indicator — 가장 명확한 신호라 최우선
    if fail_indicator and fail_indicator in body_lower:
        print("[LOGIN] failed by fail indicator", file=sys.stderr)
        return False, {}
    if success_url_keyword and success_url_keyword in final_url_lower:
        print(f"[LOGIN] success by URL keyword, cookies={len(cookies)}")
        return True, cookies

    # 2) 구조적 강한 실패: 같은 URL에 로그인 폼이 다시 출현
    if form_reappeared and not url_changed:
        print("[LOGIN] failed: login form re-appeared on same URL", file=sys.stderr)
        return False, {}

    # 3) 구조적 강한 성공: 폼 사라짐 + URL 변경 + 새 쿠키
    if not form_reappeared and url_changed and new_cookies:
        print(f"[LOGIN] success by structural signals, cookies={len(cookies)}")
        return True, cookies

    # 4) 약한 성공 신호: 위 조건 중 하나만 만족
    if not form_reappeared and (url_changed or new_cookies):
        print(f"[LOGIN] success assumed (weak signal), cookies={len(cookies)}")
        return True, cookies

    print("[LOGIN] no success evidence found", file=sys.stderr)
    return False, {}


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
    })
    return s


# 역할별 세션 쿠키 반환
def login_all_roles(
    url: str = LOGIN_URL,
    method: str = LOGIN_METHOD,
    success_url_keyword: str = LOGIN_SUCCESS_URL_KEYWORD,
    fail_indicator: str = LOGIN_FAIL_INDICATOR,
    timeout: int = _TIMEOUT,
) -> dict[str, dict]:

    roles: dict[str, dict] = {"guest": {}}

    common = dict(
        url=url, method=method,
        success_url_keyword=success_url_keyword,
        fail_indicator=fail_indicator,
        timeout=timeout,
    )

    if LOGIN_ID:
        s = _make_session()
        ok, cookies = login(s, login_id=LOGIN_ID, login_password=LOGIN_PASSWORD, **common)
        if ok:
            roles["member"] = cookies
            print(f"[AUTH - OK] member 로그인 성공: {len(cookies)} cookies")
        else:
            print("[AUTH - FAIL] member 로그인 실패. 스킵합니다", file=sys.stderr)

    if ADMIN_ID:
        s = _make_session()
        ok, cookies = login(s, login_id=ADMIN_ID, login_password=ADMIN_PASSWORD, **common)
        if ok:
            roles["admin"] = cookies
            print(f"[AUTH - OK] admin 로그인 성공: {len(cookies)} cookies")
        else:
            print("[AUTH - FAIL] admin 로그인 실패. 스킵합니다", file=sys.stderr)

    return roles
