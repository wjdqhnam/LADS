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
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("TARGET_URL", "http://localhost:8080")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "results/crawl_result.json")

LOGIN_URL = os.getenv("LOGIN_URL", "")
LOGIN_METHOD = os.getenv("LOGIN_METHOD", "POST").upper()
LOGIN_ID_FIELD = os.getenv("LOGIN_ID_FIELD", "")
LOGIN_PASSWORD_FIELD = os.getenv("LOGIN_PASSWORD_FIELD", "")
LOGIN_ID = os.getenv("LOGIN_ID", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")
LOGIN_SUCCESS_INDICATOR = os.getenv("LOGIN_SUCCESS_INDICATOR", "")
LOGIN_SUCCESS_URL_KEYWORD = os.getenv("LOGIN_SUCCESS_URL_KEYWORD", "")
LOGIN_FAIL_INDICATOR = os.getenv("LOGIN_FAIL_INDICATOR", "")

SEED_PATHS = [
    "/",
    "/bbs/login.php",
    "/bbs/register.php",
    "/bbs/faq.php",
    "/bbs/qalist.php",
    "/adm/",
    "/bbs/board.php",
    "/bbs/write.php",
    "/bbs/search.php",
    "/bbs/memo.php",
]

EXCLUDE_PATTERNS = [
    r"logout",
    r"signout",
    r"\.(jpg|jpeg|png|gif|svg|ico|css|js|pdf|zip|woff|ttf|eot)(\?|$)",
]


class CrawlConfig:
    MAX_PAGES = int(os.getenv("CRAWL_MAX_PAGES", "500"))
    MIN_PAGES = int(os.getenv("CRAWL_MIN_PAGES", "100"))
    STAGNATION_LIMIT = int(os.getenv("CRAWL_STAGNATION_LIMIT", "50"))
    DELAY = float(os.getenv("CRAWL_DELAY", "0.3"))
    TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "10"))


@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""
    options: list = field(default_factory=list)


@dataclass
class Form:
    action: str
    method: str
    fields: list = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class PageResult:
    url: str
    status_code: int
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    query_params: dict = field(default_factory=dict)
    page_title: str = ""
    is_error_page: bool = False


class Crawler:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.parsed_base = urlparse(self.base_url)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
        })
        self.auth_cookies: dict = {}
        self.visited: set[str] = set()
        self.queue: deque[str] = deque()
        self.results: list[PageResult] = []
        self.seen_input_structures: set[tuple] = set()
        self.no_new_input_pages = 0

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc == self.parsed_base.netloc

    def _is_excluded(self, url: str) -> bool:
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in EXCLUDE_PATTERNS)

    def _normalize(self, url: str) -> str:
        return urlparse(url)._replace(fragment="").geturl()

    def _query_signature(self, url: str) -> Optional[tuple]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return None
        return ("QUERY", "GET", parsed.path or "/", tuple(sorted(params.keys())))

    def _form_signature(self, form: Form) -> tuple:
        parsed = urlparse(form.action)
        return (
            "FORM",
            form.method.upper(),
            parsed.path or form.action,
            tuple(sorted(field.name for field in form.fields if field.name)),
        )

    def _should_stop_early(self, crawled: int) -> bool:
        return crawled >= CrawlConfig.MIN_PAGES and self.no_new_input_pages >= CrawlConfig.STAGNATION_LIMIT

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=CrawlConfig.TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[ERROR] fetch failed: {url} ({exc})", file=sys.stderr)
            return None

    def _extract_hidden_inputs(self, form_tag) -> dict:
        hidden = {}
        if not form_tag:
            return hidden
        for inp in form_tag.find_all("input", {"type": "hidden"}):
            name = inp.get("name")
            if name:
                hidden[name] = inp.get("value", "")
        return hidden

    def _infer_login_fields(self, form_tag, id_field: str = "", password_field: str = "") -> Optional[tuple[str, str]]:
        inputs = form_tag.find_all("input")
        password_name = password_field if password_field and form_tag.find("input", {"name": password_field}) else ""
        if not password_name:
            for inp in inputs:
                name = inp.get("name", "")
                input_type = inp.get("type", "text").lower()
                haystack = " ".join([name, inp.get("id", ""), inp.get("placeholder", ""), inp.get("autocomplete", "")]).lower()
                if name and (input_type == "password" or "pass" in haystack or "passwd" in haystack or "pw" in haystack):
                    password_name = name
                    break

        id_name = id_field if id_field and form_tag.find("input", {"name": id_field}) else ""
        if not id_name:
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
                candidates.append((score, -idx, name))
            if candidates:
                id_name = max(candidates)[2]

        if id_name and password_name:
            return id_name, password_name
        return None

    def _find_login_form(self, soup: BeautifulSoup, id_field: str = "", password_field: str = ""):
        forms = soup.find_all("form")
        if id_field and password_field:
            for form in forms:
                if form.find("input", {"name": id_field}) and form.find("input", {"name": password_field}):
                    return form
        for form in forms:
            if self._infer_login_fields(form, id_field, password_field):
                return form
        return forms[0] if forms else None

    def login(self) -> bool:
        login_url = os.getenv("LOGIN_URL", LOGIN_URL)
        if not login_url:
            return False

        login_method = os.getenv("LOGIN_METHOD", LOGIN_METHOD).upper()
        login_id_field = os.getenv("LOGIN_ID_FIELD", LOGIN_ID_FIELD)
        login_password_field = os.getenv("LOGIN_PASSWORD_FIELD", LOGIN_PASSWORD_FIELD)
        login_id = os.getenv("LOGIN_ID", LOGIN_ID)
        login_password = os.getenv("LOGIN_PASSWORD", LOGIN_PASSWORD)
        success_indicator = os.getenv("LOGIN_SUCCESS_INDICATOR", LOGIN_SUCCESS_INDICATOR).lower()
        success_url_keyword = os.getenv("LOGIN_SUCCESS_URL_KEYWORD", LOGIN_SUCCESS_URL_KEYWORD).lower()
        fail_indicator = os.getenv("LOGIN_FAIL_INDICATOR", LOGIN_FAIL_INDICATOR).lower()

        try:
            get_resp = self.session.get(login_url, timeout=CrawlConfig.TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[LOGIN] GET failed: {exc}", file=sys.stderr)
            return False

        soup = BeautifulSoup(get_resp.text, "lxml")
        form_tag = self._find_login_form(soup, login_id_field, login_password_field)
        if not form_tag:
            print("[LOGIN] login form not found", file=sys.stderr)
            return False

        inferred = self._infer_login_fields(form_tag, login_id_field, login_password_field)
        if not inferred:
            print("[LOGIN] could not infer login fields", file=sys.stderr)
            return False
        login_id_field, login_password_field = inferred

        payload = self._extract_hidden_inputs(form_tag)
        payload[login_id_field] = login_id
        payload[login_password_field] = login_password
        post_url = urljoin(login_url, form_tag.get("action")) if form_tag.get("action") else login_url

        try:
            if login_method == "GET":
                post_resp = self.session.get(post_url, params=payload, timeout=CrawlConfig.TIMEOUT, allow_redirects=True)
            else:
                post_resp = self.session.post(post_url, data=payload, timeout=CrawlConfig.TIMEOUT, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"[LOGIN] request failed: {exc}", file=sys.stderr)
            return False

        body_lower = post_resp.text.lower()
        final_url_lower = post_resp.url.lower()
        if fail_indicator and fail_indicator in body_lower:
            print("[LOGIN] failed by fail indicator", file=sys.stderr)
            return False
        if success_indicator and success_indicator in body_lower:
            self.auth_cookies = self.session.cookies.get_dict()
            print(f"[LOGIN] success by indicator, cookies={len(self.auth_cookies)}")
            return True
        if success_url_keyword and success_url_keyword in final_url_lower:
            self.auth_cookies = self.session.cookies.get_dict()
            print(f"[LOGIN] success by final URL, cookies={len(self.auth_cookies)}")
            return True
        if self.session.cookies.get_dict():
            self.auth_cookies = self.session.cookies.get_dict()
            print(f"[LOGIN] success assumed by cookies, cookies={len(self.auth_cookies)}")
            return True
        print("[LOGIN] no success evidence found", file=sys.stderr)
        return False

    def _discover_seeds(self) -> list[str]:
        seeds = {self._normalize(self.base_url + "/")}
        for path in SEED_PATHS:
            seeds.add(self._normalize(urljoin(self.base_url + "/", path)))
        return list(seeds)

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

    def crawl(self, extra_seeds: list[str] | None = None, progress_callback=None) -> list[PageResult]:
        if os.getenv("LOGIN_URL", LOGIN_URL):
            if not self.login():
                print("[WARN] login failed; continuing anonymously", file=sys.stderr)

        seeds = self._discover_seeds()
        if extra_seeds:
            seeds.extend(extra_seeds)
        for seed in seeds:
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
            parsed = urlparse(url)
            if parsed.query:
                result.query_params = parse_qs(parsed.query, keep_blank_values=True)

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
                        result.links.append(link)
                        if link not in self.visited:
                            self.queue.append(link)

            query_sig = self._query_signature(url)
            if query_sig:
                self.seen_input_structures.add(query_sig)

            self.results.append(result)
            crawled += 1
            if progress_callback:
                progress_callback(crawled, CrawlConfig.MAX_PAGES)
            if self._should_stop_early(crawled):
                print("[STOP] no new input structures recently")
                break
            time.sleep(CrawlConfig.DELAY)

        return self.results

    def save(self, path: str = OUTPUT_FILE) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(result) for result in self.results], f, ensure_ascii=False, indent=2)
        print(f"[CRAWLER] saved: {path}")

    def summary(self) -> None:
        forms = sum(len(page.forms) for page in self.results)
        queries = sum(1 for page in self.results if page.query_params)
        print(f"[CRAWLER] pages={len(self.results)}, forms={forms}, query_pages={queries}")


if __name__ == "__main__":
    crawler = Crawler(BASE_URL)
    crawler.crawl()
    crawler.save(OUTPUT_FILE)
    crawler.summary()
