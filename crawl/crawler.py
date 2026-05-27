import json
import os
import re
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup  # type: ignore[reportMissingModuleSource]
from dotenv import load_dotenv

from crawl.auth import LOGIN_URL, ensure_login_url, login as _do_login

load_dotenv()

# 대상 URL 및 결과 저장 경로
BASE_URL = os.getenv("TARGET_URL", "http://localhost:8080")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results/crawl_result.json")


# 크롤링에서 제외할 URL 패턴 (로그아웃, 정적 파일 등)
EXCLUDE_PATTERNS = [
    r"logout",
    r"signout",
    r"\.(jpg|jpeg|png|gif|svg|ico|css|js|pdf|zip|woff|ttf|eot)(\?|$)",
]

# 상태 변경 가능성 있는 링크 패턴 
DANGER_LINK_PATTERNS = [
    r"delete",
    r"remove",
    r"move",
    r"copy",
    r"update",
    r"modify",
    r"write_update",
    r"comment_update",
    r"file_delete",
    r"dbupgrade",
    r"truncate",
    r"drop",
    r"reset",
]


# 크롤링 동작 설정값
class CrawlConfig:
    MAX_PAGES = int(os.getenv("CRAWL_MAX_PAGES", "500"))               # 최대 크롤링 페이지 수
    MIN_PAGES = int(os.getenv("CRAWL_MIN_PAGES", "100"))               # 조기 종료 검사 시작 기준
    STAGNATION_LIMIT = int(os.getenv("CRAWL_STAGNATION_LIMIT", "50"))  # 새 입력 구조 없이 허용할 최대 페이지 수
    DELAY = float(os.getenv("CRAWL_DELAY", "0.3"))                     # 요청 간 딜레이 (초)
    TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "10"))                    # HTTP 요청 타임아웃 (초)


# =============================================================================
# 모델
# =============================================================================

# 폼 내 단일 입력 필드
@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""
    options: list = field(default_factory=list)


# HTML <form> 하나를 표현
@dataclass
class Form:
    action: str
    method: str
    fields: list = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


# 페이지 크롤링 결과 (URL, 상태코드, 폼, 링크, 쿼리 파라미터 등)
@dataclass
class PageResult:
    url: str
    status_code: int
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    danger_links: list = field(default_factory=list)
    query_params: dict = field(default_factory=dict)
    page_title: str = ""
    is_error_page: bool = False


# =============================================================================
# 크롤러
# =============================================================================
class Crawler:
    def __init__(self, base_url: str = BASE_URL, init_cookies: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.session = requests.Session()
        # 브라우저처럼 보이도록 User-Agent 설정
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        })

        self.init_cookies: dict | None = init_cookies
        self.auth_cookies: dict = {}
        self.visited: set[str] = set()           # 이미 방문한 URL
        self.queue: deque[str] = deque()          # 방문 예정 URL 큐
        self.results: list[PageResult] = []       # 크롤링 결과 누적
        self.seen_input_structures: set[tuple] = set()  # 중복 입력 구조 필터용 시그니처
        self.no_new_input_pages = 0              # 새 입력 구조 없는 연속 페이지 수


    # --- 
    # URL 필터링 유틸리티 
    # ---

    # 같은 도메인인지 확인
    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc == self.parsed_base.netloc

    # 제외 패턴에 해당하는 URL인지 확인
    def _is_excluded(self, url: str) -> bool:
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in EXCLUDE_PATTERNS)

    # 상태 변경 가능성이 있는 URL은 방문하지 않고 danger_links로만 수집
    def _is_danger_link(self, url: str) -> bool:
        parsed = urlparse(url)
        target = f"{parsed.path}?{parsed.query}"
        return any(re.search(pattern, target, re.IGNORECASE) for pattern in DANGER_LINK_PATTERNS)

    def _normalize(self, url: str) -> str:
        return urlparse(url)._replace(fragment="").geturl()


    # --- 
    # 중복 입력 구조 감지용 시그니처 
    # ---

    # 쿼리 파라미터 키 조합으로 GET 입력 구조 식별
    def _query_signature(self, url: str) -> Optional[tuple]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return None
        return ("QUERY", "GET", parsed.path or "/", tuple(sorted(params.keys())))

    # 폼 액션 + 메서드 + 필드명 조합으로 폼 구조 식별
    def _form_signature(self, form: Form) -> tuple:
        parsed = urlparse(form.action)
        return (
            "FORM",
            form.method.upper(),
            parsed.path or form.action,
            tuple(sorted(field.name for field in form.fields if field.name)),
        )

    # MIN_PAGES 이상 크롤 후 새 입력 구조가 STAGNATION_LIMIT 연속으로 없으면 조기 종료
    def _should_stop_early(self, crawled: int) -> bool:
        return crawled >= CrawlConfig.MIN_PAGES and self.no_new_input_pages >= CrawlConfig.STAGNATION_LIMIT

    # GET 요청, 실패 시 None 반환
    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=CrawlConfig.TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[ERROR] fetch failed: {url} ({exc})", file=sys.stderr)
            return None


    # ==========================================================================
    # 로그인
    # ==========================================================================
    
    # auth.py의 login() 호출 후 쿠키를 인스턴스에 저장
    def login(self, login_url: str = "") -> bool:
        success, cookies = _do_login(self.session, url=login_url, base_url=self.base_url)
        if success:
            self.auth_cookies = cookies
        return success

    def _parse_form(self, form_tag, page_url: str) -> Form:
        action = urljoin(page_url, form_tag.get("action") or page_url)
        method = (form_tag.get("method") or "GET").upper()
        enctype = form_tag.get("enctype") or "application/x-www-form-urlencoded"
        fields = []
        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            field_type = inp.get("type") or inp.name
            value = inp.get("value", "")
            options = [opt.get("value", opt.text.strip()) for opt in inp.find_all("option")] if inp.name == "select" else []
            fields.append(FormField(name=name, field_type=field_type, value=value, options=options))
        return Form(action=action, method=method, fields=fields, enctype=enctype)

    # 로그인 → 시드 URL 큐 적재 → BFS 크롤링 수행
    def crawl(self, extra_seeds: list[str] | None = None, progress_callback=None) -> list[PageResult]:
        if self.init_cookies is not None:
            self.session.cookies.update(self.init_cookies)
            self.auth_cookies = dict(self.init_cookies)
        else:
            login_url = os.getenv("LOGIN_URL", LOGIN_URL) or ensure_login_url(self.base_url)
            if login_url:
                if not self.login(login_url):
                    print("[WARN] login failed; continuing anonymously", file=sys.stderr)

        self.queue.append(self._normalize(self.base_url + "/"))
        for seed in (extra_seeds or []):
            self.queue.append(seed)

        crawled = 0
        while self.queue and crawled < CrawlConfig.MAX_PAGES:
            url = self.queue.popleft()
            url = self._normalize(url)
            if url in self.visited or self._is_excluded(url) or not self._is_in_scope(url):
                continue
            self.visited.add(url)

            print(f"[{crawled + 1:03d}] {url}")
            resp = self._fetch(url)
            if resp is None:
                crawled += 1
                continue

            result = PageResult(url=url, status_code=resp.status_code)

            # URL 쿼리 파라미터 저장
            parsed = urlparse(url)
            if parsed.query:
                result.query_params = parse_qs(parsed.query, keep_blank_values=True)

            # HTML 응답인 경우 폼과 링크 파싱
            content_type = resp.headers.get("content-type", "")
            if "html" in content_type.lower() or "<html" in resp.text[:500].lower():
                soup = BeautifulSoup(resp.text, "lxml")
                title = soup.find("title")
                result.page_title = title.get_text(strip=True) if title else ""

                for form_tag in soup.find_all("form"):
                    form = self._parse_form(form_tag, url)
                    result.forms.append(asdict(form))
                    self.seen_input_structures.add(self._form_signature(form))

                for a in soup.find_all("a", href=True):
                    link = self._normalize(urljoin(url, a["href"]))
                    if self._is_in_scope(link) and not self._is_excluded(link):
                        if self._is_danger_link(link):
                            result.danger_links.append({
                                "url": link,
                                "method": "GET",
                                "reason": "mutating_url",
                            })
                            continue
                        result.links.append(link)
                        if link not in self.visited:
                            self.queue.append(link)

            # 새 입력 구조 발견 여부로 stagnation 카운터 업데이트
            pre_size = len(self.seen_input_structures)

            query_sig = self._query_signature(url)
            if query_sig:
                self.seen_input_structures.add(query_sig)

            self.results.append(result)
            crawled += 1

            if len(self.seen_input_structures) == pre_size:
                self.no_new_input_pages += 1
            else:
                self.no_new_input_pages = 0

            if progress_callback:
                progress_callback(crawled, CrawlConfig.MAX_PAGES)
            if self._should_stop_early(crawled):
                print("[STOP] no new input structures recently")
                break
            time.sleep(CrawlConfig.DELAY)

        return self.results

    # 크롤링 결과를 JSON 파일로 저장
    def save(self, path: str = OUTPUT_FILE) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(result) for result in self.results], f, ensure_ascii=False, indent=2)
        print(f"[CRAWLER] saved: {path}")

    # 크롤링 통계 출력 (페이지 수, 폼 수, 쿼리 파라미터 보유 페이지 수)
    def summary(self) -> None:
        forms = sum(len(page.forms) for page in self.results)
        queries = sum(1 for page in self.results if page.query_params)
        print(f"[CRAWLER] pages={len(self.results)}, forms={forms}, query_pages={queries}")


if __name__ == "__main__":
    crawler = Crawler(BASE_URL)
    crawler.crawl()
    crawler.save(OUTPUT_FILE)
    crawler.summary()
