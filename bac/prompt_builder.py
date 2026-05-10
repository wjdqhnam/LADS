"""
bac/prompt_builder.py
BAC 탐지용 LLM 프롬프트 빌더

LLM에게 CMS별 접근 제어 정보를 질의하여 아래 항목들을 JSON으로 반환받는다:
  1. admin_paths       - 관리자 전용 경로
  2. auth_paths        - 로그인 필요 경로 (일반 회원도 포함)
  3. idor_params       - 객체 ID를 담는 파라미터 (IDOR 후보)
  4. role_params       - 권한/역할을 나타내는 파라미터
  5. sensitive_paths   - 민감 정보 노출 경로
  6. bypass_techniques - 알려진 접근 제어 우회 패턴
  7. exclude_paths     - 자동 테스트 제외 대상 (파괴적 POST 액션 등)
  8. role_hierarchy    - 권한 계층 (낮은 순 → 높은 순)
"""
from __future__ import annotations

from typing import Optional

# ── 시스템 프롬프트 ────────────────────────────────────────────────────────────

BAC_SYSTEM_PROMPT = (
    "You are a web application penetration tester specializing in "
    "Broken Access Control (OWASP A01:2021). "
    "Your task is to analyze the given web application and enumerate "
    "every possible access control test point. "
    "Output MUST be a single valid JSON object only. "
    "No markdown, no code fences, no explanations, no extra text. "
    "Every string value must be properly escaped."
)


# ── 유저 프롬프트 빌더 ─────────────────────────────────────────────────────────

def build_bac_prompt(
    cms_name: str,
    base_url: str,
    crawled_urls: Optional[list[str]] = None,
    extra_context: Optional[str] = None,
) -> str:
    """
    BAC 분석용 LLM 프롬프트 생성.

    Args:
        cms_name:      CMS 이름 및 버전 (예: "Gnuboard5 5.3.2.8")
        base_url:      타깃 기본 URL
        crawled_urls:  크롤러가 발견한 URL 목록 (없으면 생략)
        extra_context: 추가 컨텍스트 (로그인 성공 여부 등)

    Returns:
        LLM에 전달할 user prompt 문자열
    """
    crawl_section = ""
    if crawled_urls:
        # 너무 많으면 앞 80개만 (토큰 절약)
        sample = crawled_urls[:80]
        crawl_section = (
            "\n\nCRAWLED URLS (actual pages discovered on this target):\n"
            + "\n".join(f"  {u}" for u in sample)
        )

    extra_section = f"\n\nADDITIONAL CONTEXT:\n{extra_context}" if extra_context else ""

    return f"""TARGET APPLICATION
  CMS: {cms_name}
  Base URL: {base_url}{crawl_section}{extra_section}

TASK
Analyze the above application and return a comprehensive JSON object identifying
ALL potential Broken Access Control (OWASP A01:2021) test points.

Cover every category listed below. For each item include as many real, specific
entries as you know about this CMS. Do NOT omit entries to save space —
completeness is the top priority.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUIRED JSON SCHEMA
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{{
  "role_hierarchy": [
    // list of roles from LOWEST to HIGHEST privilege
    // example: ["guest", "member", "manager", "admin", "superadmin"]
  ],

  "admin_paths": [
    // Paths/endpoints that ONLY administrators should access.
    // Include ALL known admin pages, not just the top-level directory.
    {{
      "path": "/adm/",
      "description": "Admin panel root",
      "priority": 3,
      // priority: 3=high (directly dangerous), 2=medium, 1=low
      "required_params": {{}},
      // query params always needed to reach this page (e.g. {{"bo_table":"free"}})
      "notes": "Returns 302 to login for non-admin, or shows admin UI"
    }}
    // MORE ENTRIES — list every admin sub-page you know
  ],

  "auth_paths": [
    // Paths that require ANY authenticated session (member or above).
    // Guest should be blocked; logged-in member should be allowed.
    {{
      "path": "/bbs/write.php",
      "description": "Write a new post",
      "priority": 2,
      "required_params": {{"bo_table": "any_board_name"}},
      "notes": "Redirects guest to login page"
    }}
    // MORE ENTRIES
  ],

  "idor_params": [
    // Parameters that reference a specific object by ID.
    // Changing the ID value may expose another user's data.
    {{
      "param": "wr_id",
      "description": "Post/write record ID",
      "id_type": "integer",
      // id_type: integer / string / hash / uuid
      "likely_endpoints": ["/bbs/board.php", "/bbs/view.php", "/bbs/delete.php"],
      "test_strategy": "increment/decrement by 1, try wr_id=1",
      "priority": 3,
      "notes": "Private board posts should not be accessible to guest/other users"
    }},
    {{
      "param": "mb_id",
      "description": "Member/user ID (string login ID)",
      "id_type": "string",
      "likely_endpoints": ["/bbs/member_info.php", "/bbs/profile.php"],
      "test_strategy": "try known mb_id values like 'admin', enumerate via error messages",
      "priority": 3,
      "notes": "Profile/info pages may expose PII to unauthenticated users"
    }}
    // MORE ENTRIES — list EVERY parameter in this CMS that references an object by ID
    // Include: file IDs, comment IDs, message IDs, board group IDs, coupon IDs, etc.
  ],

  "role_params": [
    // URL/form parameters that encode or control the user's role/privilege.
    // Attacker may try to set these to escalate privileges.
    {{
      "param": "is_admin",
      "location": "cookie",
      // location: query / post_body / cookie / header
      "escalation_value": "1",
      "description": "Admin flag sometimes stored in cookie",
      "priority": 2
    }},
    {{
      "param": "mb_level",
      "location": "query",
      "escalation_value": "10",
      "description": "Member level; higher = more privileges",
      "priority": 3
    }}
    // MORE ENTRIES — include any role/level/permission related parameters
  ],

  "sensitive_paths": [
    // Paths that expose sensitive information (PII, credentials, config, etc.)
    // and should require proper authentication/authorization.
    {{
      "path": "/bbs/member_list.php",
      "description": "Full member list with personal information",
      "data_type": "PII",
      // data_type: PII / credentials / financial / config / logs / session
      "expected_role": "admin",
      "priority": 3
    }},
    {{
      "path": "/bbs/memo.php",
      "description": "Private messages between users",
      "data_type": "PII",
      "expected_role": "member",
      "priority": 2,
      "notes": "User should only see their own messages"
    }}
    // MORE ENTRIES
  ],

  "bypass_techniques": [
    // Known access control bypass patterns for this CMS or PHP applications in general.
    // Include parameter manipulation, header injection, URL obfuscation, etc.
    {{
      "technique": "url_case_variation",
      "description": "Uppercase letters in path may bypass .htaccess rules",
      "example": "/ADM/ instead of /adm/",
      "priority": 1
    }},
    {{
      "technique": "trailing_slash",
      "description": "Adding trailing slash may bypass access checks",
      "example": "/adm/config.php/",
      "priority": 1
    }},
    {{
      "technique": "php_extension_bypass",
      "description": "Try .php5, .phtml, .phar extensions",
      "example": "/adm/index.php5",
      "priority": 1
    }},
    {{
      "technique": "method_override_header",
      "description": "X-HTTP-Method-Override header to change request method",
      "example": "Header: X-HTTP-Method-Override: DELETE",
      "priority": 2
    }},
    {{
      "technique": "referer_spoofing",
      "description": "Some pages check Referer header instead of session for access control",
      "example": "Referer: http://target/adm/",
      "priority": 2
    }},
    {{
      "technique": "x_forwarded_for_internal",
      "description": "Spoofing X-Forwarded-For to appear as internal IP",
      "example": "X-Forwarded-For: 127.0.0.1",
      "priority": 2
    }},
    {{
      "technique": "direct_object_reference",
      "description": "Access resource files directly bypassing controller logic",
      "example": "/data/member/admin.txt, /data/file/secret.pdf",
      "priority": 3
    }},
    {{
      "technique": "path_traversal_in_param",
      "description": "Use ../ in parameters to traverse to protected paths",
      "example": "bo_table=../../adm/index",
      "priority": 2
    }},
    {{
      "technique": "null_byte_injection",
      "description": "Null byte may terminate path checks in older PHP",
      "example": "/adm/index.php%00.jpg",
      "priority": 1
    }},
    {{
      "technique": "array_param_bypass",
      "description": "Passing array instead of scalar may confuse access checks",
      "example": "mb_id[]=admin (PHP treats as array)",
      "priority": 2
    }},
    {{
      "technique": "double_encoding",
      "description": "URL double-encode special characters to bypass filters",
      "example": "/adm/%252F (double-encoded slash)",
      "priority": 1
    }}
    // MORE ENTRIES — add any CMS-specific bypass techniques you know
  ],

  "horizontal_escalation_scenarios": [
    // Specific scenarios where a user can access ANOTHER user's private data.
    // These are IDOR scenarios with concrete test steps.
    {{
      "scenario": "view_other_user_private_post",
      "description": "Access a post on a member-only board using another user's wr_id",
      "url_template": "/bbs/board.php?bo_table={{board}}&wr_id={{wr_id}}",
      "test_params": {{"bo_table": "any_private_board", "wr_id": "sequential_integer"}},
      "expected_behavior": "Should return 403 or redirect for non-member/non-owner",
      "priority": 3
    }},
    {{
      "scenario": "edit_other_user_post",
      "description": "Attempt to edit another user's post by manipulating wr_id in write form",
      "url_template": "/bbs/write.php?bo_table={{board}}&wr_id={{wr_id}}",
      "test_params": {{"bo_table": "any_board", "wr_id": "another_user_post_id"}},
      "expected_behavior": "Should check post ownership and reject non-owner",
      "priority": 3
    }},
    {{
      "scenario": "read_private_message",
      "description": "Access another user's private memo/message by changing me_id or no param",
      "url_template": "/bbs/memo.php?me_id={{me_id}}",
      "test_params": {{"me_id": "sequential_integer"}},
      "expected_behavior": "Should only show messages belonging to current session user",
      "priority": 3
    }},
    {{
      "scenario": "download_other_user_file",
      "description": "Download file attachment uploaded by another user",
      "url_template": "/bbs/download.php?bo_table={{board}}&wr_id={{wr_id}}&no={{no}}",
      "test_params": {{"bo_table": "any_board", "wr_id": "target_post_id", "no": "0"}},
      "expected_behavior": "Should enforce download permissions per board config",
      "priority": 2
    }}
    // MORE ENTRIES
  ],

  "vertical_escalation_scenarios": [
    // Specific scenarios where a low-privilege user accesses admin/higher-privilege functions.
    {{
      "scenario": "member_access_admin_panel",
      "description": "Logged-in member directly browses to /adm/ without admin rights",
      "url": "/adm/",
      "session_level": "member",
      "expected_behavior": "Should redirect to login or show permission denied",
      "priority": 3
    }},
    {{
      "scenario": "guest_access_member_area",
      "description": "Unauthenticated guest accesses member-only page",
      "url": "/bbs/write.php",
      "session_level": "guest",
      "expected_behavior": "Should redirect to login page",
      "priority": 2
    }},
    {{
      "scenario": "member_access_admin_action",
      "description": "Member attempts to execute admin action (e.g., delete any post, ban user)",
      "url": "/adm/board_list_update.php",
      "session_level": "member",
      "expected_behavior": "Should reject non-admin session",
      "priority": 3
    }}
    // MORE ENTRIES — list every admin action a regular member should NOT be able to do
  ],

  "exclude_paths": [
    // Paths that should NOT be auto-tested because they cause permanent data changes.
    // These require manual testing only.
    // Include all DELETE, UPDATE, INSERT endpoints.
    "/bbs/delete.php",
    "/bbs/delete_comment.php",
    "/bbs/write_update.php",
    "/adm/member_del.php",
    "/adm/board_list_delete.php"
    // MORE — add any path that modifies/deletes data
  ],

  "cms_specific_notes": {{
    // Any important CMS-specific access control implementation details
    // that affect how tests should be designed or interpreted.
    "auth_cookie_name": "PHPSESSID",
    "admin_check_mechanism": "Session variable 'is_admin' set to 1 after admin login",
    "member_level_field": "mb_level (1-10, default 2 for normal members)",
    "board_access_config": "Each board has its own read/write/comment level settings",
    "known_vulnerabilities": [
      "CVE-XXXX-XXXX: Description of known BAC vulnerability in this CMS version"
    ],
    "additional_notes": "Any other relevant information for BAC testing"
  }}
}}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IMPORTANT RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Output valid JSON only. No markdown, no extra text.
2. Be EXHAUSTIVE — include every admin page, every IDOR parameter, every bypass technique you know for this CMS.
3. Use the crawled URLs above to add entries you see in the actual target.
4. Set priority=3 for critical findings (direct privilege escalation, PII exposure).
5. For admin_paths, list EVERY sub-page under /adm/ and /admin/ you know, not just the root.
6. For idor_params, list EVERY parameter that references an object by ID in the entire CMS.
7. For bypass_techniques, include both generic PHP/web bypass patterns AND CMS-specific ones.
8. For exclude_paths, be conservative — err on the side of including more exclusions.
"""


# ── 응답 파서 (LLM JSON 응답 → 정형 구조체) ─────────────────────────────────

import json
import re


def parse_bac_response(raw: str) -> dict:
    """
    LLM 응답에서 JSON 추출 및 파싱.

    LLM이 가끔 JSON 앞뒤에 설명을 붙이거나 ```json 코드블록을 쓰는 경우 처리.

    Returns:
        파싱된 dict. 실패 시 빈 dict 반환.
    """
    # 코드블록 제거
    text = re.sub(r"```(?:json)?", "", raw).strip()

    # 첫 번째 { 부터 마지막 } 까지 추출
    start = text.find("{")
    end   = text.rfind("}")
    if start == -1 or end == -1:
        return {}

    try:
        return json.loads(text[start: end + 1])
    except json.JSONDecodeError:
        # 간단한 fallback: 줄별로 주석 제거 후 재시도
        cleaned_lines = []
        for line in text[start: end + 1].splitlines():
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            # 인라인 주석 제거 (문자열 외부의 // 이후)
            line = re.sub(r"\s*//[^\"']*$", "", line)
            cleaned_lines.append(line)
        cleaned = "\n".join(cleaned_lines)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {}


# ── 결과 요약 출력 ─────────────────────────────────────────────────────────────

def summarize(bac_data: dict) -> None:
    """parse_bac_response 결과를 콘솔에 요약 출력."""
    if not bac_data:
        print("[BAC] LLM 응답 파싱 실패 또는 빈 응답")
        return

    print(f"[BAC] role_hierarchy        : {bac_data.get('role_hierarchy', [])}")
    print(f"[BAC] admin_paths           : {len(bac_data.get('admin_paths', []))}개")
    print(f"[BAC] auth_paths            : {len(bac_data.get('auth_paths', []))}개")
    print(f"[BAC] idor_params           : {len(bac_data.get('idor_params', []))}개")
    print(f"[BAC] role_params           : {len(bac_data.get('role_params', []))}개")
    print(f"[BAC] sensitive_paths       : {len(bac_data.get('sensitive_paths', []))}개")
    print(f"[BAC] bypass_techniques     : {len(bac_data.get('bypass_techniques', []))}개")
    print(f"[BAC] horiz. scenarios      : {len(bac_data.get('horizontal_escalation_scenarios', []))}개")
    print(f"[BAC] vert. scenarios       : {len(bac_data.get('vertical_escalation_scenarios', []))}개")
    print(f"[BAC] exclude_paths         : {len(bac_data.get('exclude_paths', []))}개")


# ── 직접 실행 시 프롬프트 미리보기 ─────────────────────────────────────────────

if __name__ == "__main__":
    sample_urls = [
        "http://target/bbs/board.php?bo_table=free",
        "http://target/bbs/write.php?bo_table=free",
        "http://target/bbs/search.php",
        "http://target/bbs/login.php",
        "http://target/adm/",
        "http://target/bbs/member_info.php?mb_id=admin",
    ]

    prompt = build_bac_prompt(
        cms_name="Gnuboard5 5.3.2.8",
        base_url="http://target",
        crawled_urls=sample_urls,
    )

    print("=== SYSTEM PROMPT ===")
    print(BAC_SYSTEM_PROMPT)
    print("\n=== USER PROMPT ===")
    print(prompt)
    print(f"\n[총 user prompt 길이: {len(prompt)} chars]")
