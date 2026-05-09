# LADS 프로젝트 정리

## 프로젝트 목표

**"LLM 기반 CMS 웹 취약점 자동 탐지 파이프라인"**

LLM이 CMS별 입력 지점과 취약점 유형을 바탕으로 테스트 시나리오/페이로드를 생성하고,
DAST 방식으로 자동 실행·검증해서 취약점을 탐지한다.

- **핵심 구현**: SQLi, XSS
- **확장 구현**: BAC, Misconfiguration
- **대상 CMS**: Gnuboard5 우선, 이후 WordPress 확장 가능 구조
- **메인 파이프라인**: `crawl → target → LLM → fuzz → validate → findings`
- **제거 대상**: `scanner.py` 중심 레거시 흐름

---

## 발표용 한 줄 정의

> 본 프로젝트는 OWASP Top 10의 주요 웹 취약점 중 SQL Injection과 XSS를 핵심 자동 탐지 대상으로 구현하고, Broken Access Control과 Security Misconfiguration은 CMS 환경에서 안전하게 자동화 가능한 범위의 점검 모듈로 확장한다. BAC는 완전 자동 판정이 어렵기 때문에 세션별 응답 비교 기반의 의심 탐지로 제한했으며, 이는 설계상 의도된 보수적 접근이다.

---

## 목표 디렉토리 구조

```
LADS/
├── crawler.py
├── target_builder.py
├── payload/
│   ├── context_builder.py   # 그누보드 특화 코드 제거, 범용화
│   ├── generate_payloads.py
│   ├── llm_client.py
│   ├── parser.py            # payload_parser.py 이름 변경, 중복 제거 전담
│   └── validator.py         # payload_filter.py 대체, 유효성 판단 전담
├── baseline/
│   ├── sqli.py
│   └── xss.py
├── fuzzer/
│   ├── fuzzing_strategy.py
│   ├── executor.py
│   └── validator.py         # analyzer/ 통합, 취약 판정 전담
├── bac/                     # 신규
│   ├── candidate_extractor.py
│   ├── session_manager.py
│   └── comparator.py
├── misconfig/               # 신규
│   └── checker.py
├── app.py
└── tasks.py
```

---

## 전체 파이프라인 흐름

```
[크롤링] crawler.py
  → crawl_result.json
  → target_builder.py → targets.json

[페이로드 생성] payload/generate_payloads.py
  → INPUT_POINTS 순회
  → context_builder.build_prompt() → LLMClient.generate()
  → payload/validator.py (유효성 판단)
  → payload/parser.py (파싱 + 중복 제거)
  → results/payloads_llm.json
  → results/payloads_llm_meta.json

[퍼징] fuzzer/fuzzing_strategy.py
  → fuzz_tasks.json

[실행] fuzzer/executor.py
  → execution_results.json

[판정] fuzzer/validator.py
  → results/findings.json

[BAC] bac/
  → candidate_extractor.py → 후보 URL scoring
  → session_manager.py → guest/user/admin 세션
  → comparator.py → 응답 비교 + 판정
  → results/findings.json

[Misconfig] misconfig/checker.py
  → GET/HEAD 요청 → 룰 기반 검증
  → results/findings.json

[대시보드] app.py
  → Flask SSE 스트림으로 단계별 실행
```

---

## findings.json 공통 포맷

모든 모듈(SQLi, XSS, BAC, Misconfig)이 동일한 포맷으로 저장.

```json
{
  "module": "sqli",
  "type": "SQLI_CONFIRMED",
  "category": "error_based",
  "url": "/bbs/search.php",
  "param": "stx",
  "payload": "a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))#",
  "status": 200,
  "confidence": "high",
  "evidence": "xpath syntax error found in response"
}
```

| 필드 | 설명 |
|---|---|
| `module` | sqli / xss / bac / misconfig |
| `type` | SQLI_CONFIRMED, BAC_SUSPECTED, MISCONFIG_CONFIRMED 등 |
| `category` | error_based, reflected, admin_area, git_exposure 등 |
| `confidence` | high / medium / low |
| `evidence` | 판정 근거 문자열 |

---

## 각 모듈 상세

### SQLi / XSS
- 핵심 구현, 자동 확정 판정 가능
- SQLi: Blind, Time-based, Boolean-based, Error-based
- XSS: Reflected 자동 검증, Stored는 저장 후 조회 검증까지 가능한 범위

### BAC

**설계 원칙**: CMS 설정 없어도 동작, 설정 있으면 정확도 향상

**세션 구조**
| 단계 | 세션 | confidence |
|---|---|---|
| 1단계 | guest only | LOW |
| 2단계 | guest + user | MEDIUM |
| 3단계 | guest + user + admin | HIGH |

**후보 URL 점수화**
```
+3  path에 admin/manage/dashboard/settings
+2  path에 profile/account/user/member
+2  param에 id/user_id/post_id/file_id/mb_id/wr_id
+2  로그인 세션에서 발견, guest 크롤에는 없음
+3  guest 요청 시 redirect, user 요청 시 200
-5  method POST + delete/update/save 포함
```

**자동 실행 제외**: POST, delete/update/save/write/create 포함 URL, form submission

**판정 기준**
- guest가 200 + 로그인 키워드 없음 → `BAC_SUSPECTED_LOW`
- user가 admin URL에 200 + admin keyword → `BAC_SUSPECTED_MEDIUM`
- user 응답이 admin 응답과 유사 → `BAC_SUSPECTED_HIGH`
- id 파라미터 ±1 변형 후 200 + 정상 구조 → `IDOR_SUSPECTED`

**CMS 프로파일 (선택)**
- Generic rule 기본 동작
- LLM에게 CMS-specific hint 질의 후 merge
- 실제 crawler 결과와 교차 검증

### Misconfiguration

**체크 항목**
```
민감 파일:  /.env, /.git/config, /composer.json
백업 파일:  /config.php.bak, /index.php.bak
디렉토리:   /data/, /uploads/, /theme/
phpinfo:    /phpinfo.php, /info.php
보안 헤더:  X-Frame-Options, X-Content-Type-Options, CSP
버전 노출:  Server, X-Powered-By
```

**판정 기준**
| 체크 | 조건 | 결과 |
|---|---|---|
| `.env` | 200 + DB_PASSWORD/SECRET 키워드 | CONFIRMED |
| `.git/config` | 200 + `[core]` 키워드 | CONFIRMED |
| directory listing | 200 + `Index of /` | CONFIRMED |
| phpinfo | 200 + `PHP Version` | CONFIRMED |
| error disclosure | Fatal error / SQL syntax | CONFIRMED |
| 보안 헤더 누락 | 헤더 없음 | WARNING |

---

## 현재 코드 상태

### 버그 (수정 필요)
- `xss_qalist_stx` URL 불일치: generate_payloads는 `board.php`, scanner는 `qalist.php`
- executor 결과 필드명 불일치: `status/length/elapsed` vs `status_code/response_length/response_time`
- validator TIME_BASED 탐지 안 됨: `vuln_type`에 "time" 문자열 없어서 미동작
- `_task_all()` 미완성: fuzz → execute → validate 단계 빠져 있음

### Dead Code
- `analyzer/` 폴더 전체 — 어디서도 사용 안 함

---

## PR 순서 (권장)

1. findings 공통 스키마 정의
2. `scanner.py` 삭제
3. `analyzer/` → `fuzzer/validator.py` 통합
4. `payload_filter.py` → `payload/validator.py` 리네임/정리
5. `payload_parser.py` → `payload/parser.py` 리네임/정리
6. `misconfig/checker.py` 추가
7. `bac/` 1단계 (guest only)
8. `bac/` 2단계 (user 세션)

---

## 팀원별 태스크

### 팀원1
- `fuzzer/validator.py` + `analyzer/` 통합
- 페이로드 중복 제거

### 팀원3 (나)
- 그누보드 특화 코드 제거/수정 (`context_builder.py`)
- LLM 프롬프트 예시 → baseline payload로 대체
- 페이로드 유효성 판단기 제작 (`payload/validator.py`)
- findings 공통 포맷 정의

### 공통
- `scanner.py` 제거 (이번 주 목표)
- 커밋 잘게, 기능 하나당 PR

---

## 주간 작업 내용

### 1주차 (2026-05-07)

**페이로드 생성 환경 설정**
- 출력 파일명 `payloads_llm.json`으로 통일
- COUNT 5 → 7 증가 (입력 포인트당 LLM 생성 페이로드 수 확대)
- `load_dotenv()` 적용 및 `.env` 파일 생성
- `results/` 디렉토리 자동 생성 로직 추가

**LLM 프롬프트 개선**
- 모든 빌더에 `ONLY USE THIS TYPE: X` 타입 강제 선언 추가
- 예시 페이로드 2~4개 → 7~9개로 확장
- 제약 조건 리마인더 예시 근처에 반복 삽입
- `SQLI_ERROR` → `ERROR_BASED` 타입명 통일
- 잘못된 MySQL 문법 수정 (`FROM/**/table`, `LIMIT/**/n,m`, `/**/` 스페이스 대체)

**페이로드 필터 패턴 수정**
- `BOOLEAN` 패턴에 `OR\(|AND\(|SELECT` 추가
- `SQLI_FIELD` 패턴에 `AND\(|OR\(` 추가
- sqli_search_stx 통과 페이로드 4개 → 7개로 증가

**스캔 결과 확인 (Gnuboard5 대상)**
- `xss_search_stx`: Reflected XSS 4개 탐지
- `sqli_search_stx`: SQLi 10개 탐지 (Boolean + Error-based, DB/테이블/패스워드 추출 가능 확인)
