"""
bac/session_manager.py
BAC 테스트용 세션 관리

세션 단계:
  - guest:  비인증 (쿠키 없음)
  - member: 일반 회원 로그인
  - admin:  관리자 로그인

설정 우선순위:
  1. 생성자 직접 주입 (cookies dict)
  2. 크롤러가 저장한 auth_cookies.json
  3. .env 파일의 계정 정보로 자동 로그인
  4. 없으면 guest만 사용
"""
from __future__ import annotations

import json
import os
from typing import Optional

import requests

_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
}

# ── 세션 레벨 상수 ────────────────────────────────────────────────────────────
GUEST  = "guest"
MEMBER = "member"
ADMIN  = "admin"

ALL_LEVELS = [GUEST, MEMBER, ADMIN]


class SessionManager:
    """
    guest / member / admin 세션을 생성 및 관리.

    사용 예:
        sm = SessionManager(base_url="http://target")
        sm.load_from_cookies_file("runs/run_xxx/auth_cookies.json")
        sm.login_member(login_url="/bbs/login_check.php", mb_id="user1", mb_password="pw")

        sessions = sm.get_sessions(["guest", "member"])
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._sessions: dict[str, requests.Session] = {}

        # guest는 항상 존재
        self._sessions[GUEST] = self._new_session()

    # ── 세션 생성 헬퍼 ────────────────────────────────────────────────────────

    def _new_session(self, cookies: dict = None) -> requests.Session:
        s = requests.Session()
        s.headers.update(_DEFAULT_HEADERS)
        if cookies:
            s.cookies.update(cookies)
        return s

    # ── 쿠키 파일에서 로드 ────────────────────────────────────────────────────

    def load_from_cookies_file(self, path: str, level: str = MEMBER) -> bool:
        """
        크롤러가 저장한 auth_cookies.json에서 세션 로드.

        Args:
            path:  쿠키 파일 경로
            level: 어떤 세션으로 등록할지 (member / admin)

        Returns:
            성공 여부
        """
        if not os.path.exists(path):
            print(f"[SESSION] 쿠키 파일 없음: {path}")
            return False
        try:
            with open(path, encoding="utf-8") as f:
                cookies = json.load(f)
            self._sessions[level] = self._new_session(cookies)
            print(f"[SESSION] {level} 세션 로드 완료 (쿠키 파일: {path})")
            return True
        except Exception as e:
            print(f"[SESSION] 쿠키 파일 로드 실패: {e}")
            return False

    # ── 자동 로그인 ───────────────────────────────────────────────────────────

    def login(
        self,
        login_url: str,
        credentials: dict,
        level: str = MEMBER,
        success_check: Optional[str] = None,
    ) -> bool:
        """
        POST 로그인 후 세션 저장.

        Args:
            login_url:     로그인 처리 URL (예: /bbs/login_check.php)
            credentials:   POST 데이터 (예: {"mb_id": "user", "mb_password": "pw"})
            level:         저장할 세션 레벨
            success_check: 로그인 성공 여부 확인할 키워드 (응답 URL 또는 body)

        Returns:
            성공 여부
        """
        s = self._new_session()
        url = self.base_url + login_url

        try:
            resp = s.post(url, data=credentials, timeout=self.timeout, allow_redirects=True)
            # 로그인 성공 판단: PHPSESSID 또는 로그인 관련 쿠키 확인
            has_session = any(
                "PHPSESSID" in k or "sess" in k.lower()
                for k in s.cookies.keys()
            )
            if success_check:
                has_session = has_session or (success_check in resp.url or success_check in resp.text)

            if has_session:
                self._sessions[level] = s
                print(f"[SESSION] {level} 로그인 성공: {url}")
                return True
            else:
                print(f"[SESSION] {level} 로그인 실패 (세션 쿠키 없음): {url}")
                return False
        except Exception as e:
            print(f"[SESSION] {level} 로그인 오류: {e}")
            return False

    def login_from_env(
        self,
        login_url: str = "/bbs/login_check.php",
        level: str = MEMBER,
    ) -> bool:
        """
        .env의 BAC_MB_ID / BAC_MB_PASSWORD (또는 BAC_ADMIN_ID / BAC_ADMIN_PASSWORD) 로 자동 로그인.

        .env 키 규칙:
            member: BAC_MB_ID, BAC_MB_PASSWORD
            admin:  BAC_ADMIN_ID, BAC_ADMIN_PASSWORD
        """
        if level == MEMBER:
            mb_id  = os.getenv("BAC_MB_ID", "")
            mb_pw  = os.getenv("BAC_MB_PASSWORD", "")
        else:
            mb_id  = os.getenv("BAC_ADMIN_ID", "")
            mb_pw  = os.getenv("BAC_ADMIN_PASSWORD", "")

        if not mb_id or not mb_pw:
            print(f"[SESSION] {level} 계정 정보 없음 (.env BAC_MB_ID/BAC_MB_PASSWORD 확인)")
            return False

        return self.login(
            login_url=login_url,
            credentials={"mb_id": mb_id, "mb_password": mb_pw, "url": "/"},
            level=level,
        )

    # ── 세션 유효성 확인 ──────────────────────────────────────────────────────

    def validate_session(self, level: str, check_url: str = "/") -> bool:
        """세션이 여전히 유효한지 확인 (로그인 키워드 체크)."""
        if level not in self._sessions:
            return False

        _LOGIN_KEYWORDS = ["로그아웃", "마이페이지", "logout", "mypage", "mb_id"]

        try:
            resp = self._sessions[level].get(
                self.base_url + check_url,
                timeout=self.timeout,
                allow_redirects=True,
            )
            return any(kw in resp.text for kw in _LOGIN_KEYWORDS)
        except Exception:
            return False

    # ── 세션 조회 ─────────────────────────────────────────────────────────────

    def get_session(self, level: str) -> Optional[requests.Session]:
        return self._sessions.get(level)

    def get_sessions(self, levels: list[str]) -> dict[str, requests.Session]:
        """요청한 레벨 중 사용 가능한 세션만 반환."""
        return {
            lvl: self._sessions[lvl]
            for lvl in levels
            if lvl in self._sessions
        }

    def available_levels(self) -> list[str]:
        return list(self._sessions.keys())

    # ── 팩토리: 자동 세팅 ─────────────────────────────────────────────────────

    @classmethod
    def from_run(
        cls,
        base_url: str,
        run_dir: str,
        login_url: str = "/bbs/login_check.php",
        timeout: int = 10,
    ) -> "SessionManager":
        """
        run 디렉토리의 auth_cookies.json + .env 계정으로 자동 구성.

        우선순위:
          1. auth_cookies.json → member 세션
          2. .env BAC_MB_ID/PW → member 로그인
          3. .env BAC_ADMIN_ID/PW → admin 로그인
        """
        sm = cls(base_url=base_url, timeout=timeout)

        cookies_file = os.path.join(run_dir, "auth_cookies.json")
        if os.path.exists(cookies_file):
            sm.load_from_cookies_file(cookies_file, level=MEMBER)
        else:
            sm.login_from_env(login_url=login_url, level=MEMBER)

        sm.login_from_env(login_url=login_url, level=ADMIN)

        print(f"[SESSION] 사용 가능 레벨: {sm.available_levels()}")
        return sm
