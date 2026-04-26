import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
from dotenv import load_dotenv
import json
import time
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

load_dotenv()

BASE_URL   = os.getenv("TARGET_URL", "http://localhost")
MAX_PAGES  = int(os.getenv("MAX_PAGES", 300))
DELAY      = float(os.getenv("DELAY", 0.3))
TIMEOUT    = int(os.getenv("TIMEOUT", 10))
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "crawl_result.json")

LOGIN_URL      = os.getenv("LOGIN_URL", "")
LOGIN_ID       = os.getenv("LOGIN_ID", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")

# robots.txt/sitemap.xml 자동 발견 실패 시 사용하는 fallback 경로
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

# 크롤링 제외 패턴 (로그아웃·삭제 등 상태 변경 위험 액션)
EXCLUDE_PATTERNS = [
    r"logout", r"signout",
    r"\.(jpg|jpeg|png|gif|svg|ico|css|js|pdf|zip|woff|ttf|eot)(\?|$)",
]


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
        self.parsed_base = urlparse(base_url)

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

        self.visited: set[str] = set()
        self.queue: deque[str] = deque()
        self.results: list[PageResult] = []

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return (
            parsed.scheme in ("http", "https")
            and parsed.netloc == self.parsed_base.netloc
        )

    def _is_excluded(self, url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in EXCLUDE_PATTERNS)

    def _normalize(self, url: str) -> str:
        return urlparse(url)._replace(fragment="").geturl()

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[Form]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = urljoin(page_url, form_tag.get("action", page_url))
            method = form_tag.get("method", "GET").upper()
            enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")
            fields = []

            for inp in form_tag.find_all(["input", "textarea", "select", "button"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "select":
                    opts = [o.get("value", o.get_text(strip=True))
                            for o in inp.find_all("option")]
                    fields.append(FormField(name=name, field_type="select",
                                            value=opts[0] if opts else "", options=opts))
                elif inp.name == "textarea":
                    fields.append(FormField(name=name, field_type="textarea",
                                            value=inp.get_text(strip=True)))
                else:
                    fields.append(FormField(name=name,
                                            field_type=inp.get("type", "text"),
                                            value=inp.get("value", "")))
            forms.append(Form(action=action, method=method,
                              fields=fields, enctype=enctype))
        return forms

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            normalized = self._normalize(urljoin(page_url, href))
            if self._is_in_scope(normalized) and not self._is_excluded(normalized):
                links.append(normalized)
        return links

    def _parse_sitemap(self, url: str) -> set[str]:
        urls = set()
        resp = self._fetch(url)
        if not resp or resp.status_code != 200:
            return urls
        text = resp.text.strip()
        if not text.startswith("<?xml") and "<urlset" not in text and "<sitemapindex" not in text:
            return urls
        soup = BeautifulSoup(text, "lxml-xml")
        for sitemap_tag in soup.find_all("sitemap"):
            loc = sitemap_tag.find("loc")
            if loc:
                urls.update(self._parse_sitemap(loc.get_text(strip=True)))
        for url_tag in soup.find_all("url"):
            loc = url_tag.find("loc")
            if loc:
                u = self._normalize(loc.get_text(strip=True))
                if self._is_in_scope(u) and not self._is_excluded(u):
                    urls.add(u)
        return urls

    def _extract_paths_from_js(self, js_url: str) -> set[str]:
        urls = set()
        resp = self._fetch(js_url)
        if not resp or resp.status_code != 200:
            return urls
        paths = re.findall(r'["\'](/(?:bbs|adm|board|common|shop|gnu)[^"\'?\s]*)["\']', resp.text)
        for path in paths:
            u = self._normalize(self.base_url + path)
            if self._is_in_scope(u) and not self._is_excluded(u):
                urls.add(u)
        return urls

    def _discover_seeds(self) -> list[str]:
        seeds: set[str] = set()

        # 1. robots.txt
        resp = self._fetch(self.base_url + "/robots.txt")
        if resp and resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip().split("*")[0]
                    if path and path != "/":
                        u = self._normalize(self.base_url + path)
                        if self._is_in_scope(u) and not self._is_excluded(u):
                            seeds.add(u)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    found = self._parse_sitemap(sitemap_url)
                    if found:
                        print(f"[SPIDER] robots.txt Sitemap 지시자: {len(found)}개 URL")
                    seeds.update(found)

        # 2. sitemap.xml / sitemap_index.xml
        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml"]:
            found = self._parse_sitemap(self.base_url + sitemap_path)
            if found:
                print(f"[SPIDER] {sitemap_path}: {len(found)}개 URL 발견")
            seeds.update(found)

        # 3. 메인 페이지 JS 파일에서 경로 추출
        main_resp = self._fetch(self.base_url + "/")
        if main_resp and "text/html" in main_resp.headers.get("Content-Type", ""):
            soup = BeautifulSoup(main_resp.text, "lxml")
            js_found = 0
            for script in soup.find_all("script", src=True):
                js_url = urljoin(self.base_url, script["src"])
                if self._is_in_scope(js_url):
                    found = self._extract_paths_from_js(js_url)
                    js_found += len(found)
                    seeds.update(found)
            if js_found:
                print(f"[SPIDER] JS 파일 분석: {js_found}개 경로 발견")

        # 항상 루트는 포함
        seeds.add(self._normalize(self.base_url + "/"))

        # 4. fallback
        if len(seeds) <= 1:
            print("[SPIDER] 자동 발견 실패 — 기본 SEED_PATHS 사용")
            return [self.base_url + p for p in SEED_PATHS]

        print(f"[SPIDER] 자동 발견 완료: {len(seeds)}개 시드")
        return list(seeds)

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            print(f"  [ERROR] {url} — {e}", file=sys.stderr)
            return None

    def crawl(self, extra_seeds: list[str] = None) -> list[PageResult]:
        seeds = self._discover_seeds()
        if extra_seeds:
            seeds.extend(extra_seeds)
        for s in seeds:
            self.queue.append(s)

        crawled = 0
        while self.queue and crawled < MAX_PAGES:
            url = self.queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            print(f"[{crawled+1:03d}] {url}")
            resp = self._fetch(url)
            if resp is None:
                crawled += 1
                continue

            result = PageResult(url=url, status_code=resp.status_code)

            parsed = urlparse(url)
            if parsed.query:
                result.query_params = parse_qs(parsed.query, keep_blank_values=True)

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                self.results.append(result)
                crawled += 1
                time.sleep(DELAY)
                continue

            # PHP 에러 페이지 감지
            if "Fatal error" in resp.text or "Warning" in resp.text[:200]:
                result.is_error_page = True
                print(f"       [PHP ERROR] {url}")
                self.results.append(result)
                crawled += 1
                time.sleep(DELAY)
                continue

            soup = BeautifulSoup(resp.text, "lxml")
            title = soup.find("title")
            result.page_title = title.get_text(strip=True) if title else ""
            result.forms = self._extract_forms(soup, url)
            result.links = self._extract_links(soup, url)

            for link in result.links:
                if link not in self.visited:
                    self.queue.append(link)

            self.results.append(result)
            crawled += 1
            time.sleep(DELAY)

        print(f"\n크롤링 완료: {crawled}페이지 방문")
        return self.results

    def save(self, path: str = OUTPUT_FILE):
        data = []
        for r in self.results:
            data.append({
                "url": r.url,
                "status_code": r.status_code,
                "page_title": r.page_title,
                "is_error_page": r.is_error_page,
                "query_params": r.query_params,
                "forms": [
                    {
                        "action": f.action,
                        "method": f.method,
                        "enctype": f.enctype,
                        "fields": [asdict(ff) for ff in f.fields],
                    }
                    for f in r.forms
                ],
                "links_count": len(r.links),
            })
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
        print(f"결과 저장: {path}")

    def summary(self):
        ok_pages = [r for r in self.results if not r.is_error_page]
        err_pages = [r for r in self.results if r.is_error_page]
        all_forms = [(r.url, f) for r in ok_pages for f in r.forms]
        urls_with_params = [r for r in self.results if r.query_params]
        post_forms = [(url, f) for url, f in all_forms if f.method == "POST"]
        get_forms = [(url, f) for url, f in all_forms if f.method == "GET"]

        sep = "=" * 60
        print(f"\n{sep}")
        print("DAST 공격 표면 요약")
        print(sep)
        print(f"총 방문 페이지        : {len(self.results)}")
        print(f"  정상 페이지         : {len(ok_pages)}")
        print(f"  PHP 에러 페이지     : {len(err_pages)}")
        print(f"URL 파라미터 페이지   : {len(urls_with_params)}")
        print(f"Form 총 개수          : {len(all_forms)}")
        print(f"  POST form           : {len(post_forms)}")
        print(f"  GET form            : {len(get_forms)}")

        if post_forms:
            print("\n[POST Form 목록]")
            for url, f in post_forms:
                fields_str = [ff.name for ff in f.fields]
                print(f"  URL    : {url}")
                print(f"  action : {f.action}")
                print(f"  fields : {fields_str}")
                print()

        if urls_with_params:
            print(f"\n[URL 파라미터 (상위 15개)]")
            for r in urls_with_params[:15]:
                print(f"  {r.url}")
                print(f"    params: {list(r.query_params.keys())}")

        if err_pages:
            print(f"\n[PHP 에러 페이지 (상위 10개)]")
            for r in err_pages[:10]:
                print(f"  {r.url}  (HTTP {r.status_code})")


if __name__ == "__main__":
    if not BASE_URL or BASE_URL == "http://localhost":
        print("[ERROR] TARGET_URL이 .env에 설정되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    crawler = Crawler(BASE_URL)
    crawler.crawl()
    crawler.save()
    crawler.summary()
