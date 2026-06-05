"""
OWASP Benchmark XSS 스캔 스크립트
- 456개 XSS 테스트케이스에 페이로드 주입
- validate_xss()로 판정
- expectedresults-1.2.csv와 비교해서 TP/FP/TN/FN 계산
"""
import csv
import os
import re
import sys
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.dirname(__file__))
from analyzer.xss_analyzer import validate_xss

BENCHMARK_BASE   = "https://localhost:8443/benchmark"
JAVA_SRC         = r"C:\Users\admin\BenchmarkJava\src\main\java\org\owasp\benchmark\testcode"
EXPECTED_CSV     = r"C:\Users\admin\BenchmarkJava\expectedresults-1.2.csv"
XSS_PAYLOAD      = "onerror=alert"
TIMEOUT          = 5

# ── 테스트케이스 파싱 ──────────────────────────────────────────────────────────

def parse_test_case(name: str) -> dict | None:
    path = os.path.join(JAVA_SRC, f"{name}.java")
    if not os.path.exists(path):
        return None
    src = open(path, encoding="utf-8").read()

    # URL 경로 (@WebServlet)
    m = re.search(r'@WebServlet\(value\s*=\s*"([^"]+)"', src)
    if not m:
        return None
    url_path = m.group(1)

    # 입력 소스 판단
    if 'getHeaders("Referer")' in src or 'getHeader("Referer")' in src:
        input_type = "referer"
        param_name = None
    elif 'getCookies()' in src:
        input_type = "cookie"
        m2 = re.search(r'getTheParameter\("([^"]+)"\)', src)
        param_name = m2.group(1) if m2 else name
    elif 'getQueryString()' in src:
        # getQueryString()은 POST body가 아니라 URL query string에서 읽음 → GET 필요
        input_type = "query_string"
        param_name = name
    elif 'getTheParameter' in src:
        input_type = "param"
        m2 = re.search(r'getTheParameter\("([^"]+)"\)', src)
        param_name = m2.group(1) if m2 else name
    elif 'getParameterMap' in src or 'getParameterNames' in src:
        input_type = "param"
        param_name = name
    elif 'getParameter(' in src:
        input_type = "param"
        m2 = re.search(r'getParameter\("([^"]+)"\)', src)
        param_name = m2.group(1) if m2 else name
    else:
        input_type = "param"
        param_name = name

    return {
        "name": name,
        "url": f"{BENCHMARK_BASE}{url_path}",
        "input_type": input_type,
        "param_name": param_name,
    }


# ── 요청 전송 ─────────────────────────────────────────────────────────────────

def send_request(tc: dict, payload: str) -> dict:
    session = requests.Session()
    try:
        if tc["input_type"] == "referer":
            resp = session.get(
                tc["url"], headers={"Referer": payload},
                timeout=TIMEOUT, verify=False
            )
        elif tc["input_type"] == "query_string":
            resp = session.get(
                tc["url"], params={tc["param_name"]: payload},
                timeout=TIMEOUT, verify=False
            )
        elif tc["input_type"] == "cookie":
            resp = session.get(
                tc["url"], cookies={tc["param_name"]: payload},
                timeout=TIMEOUT, verify=False
            )
        else:
            resp = session.post(
                tc["url"], data={tc["param_name"]: payload},
                timeout=TIMEOUT, verify=False
            )
        return {
            "status": resp.status_code,
            "response_body": resp.text[:20000],
            "payload": payload,
            "error": None,
        }
    except requests.Timeout:
        return {"status": None, "response_body": None, "payload": payload, "error": "timeout"}
    except Exception as e:
        return {"status": None, "response_body": None, "payload": payload, "error": str(e)}


# ── 정답 로드 ─────────────────────────────────────────────────────────────────

def load_expected(csv_path: str) -> dict[str, bool]:
    expected = {}
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, *_ = row
            if category.strip() == "xss":
                expected[name.strip()] = (real.strip() == "true")
    return expected


# ── 메인 ─────────────────────────────────────────────────────────────────────

def main():
    print("OWASP Benchmark XSS 스캔 시작")
    expected = load_expected(EXPECTED_CSV)
    xss_cases = [k for k, v in expected.items()]
    print(f"XSS 테스트케이스: {len(xss_cases)}개 (취약 {sum(expected.values())}개, 안전 {sum(not v for v in expected.values())}개)")

    tp = fp = tn = fn = err = 0
    results = []

    for i, name in enumerate(xss_cases, 1):
        tc = parse_test_case(name)
        if not tc:
            err += 1
            continue

        raw = send_request(tc, XSS_PAYLOAD)
        found, evidence, xss_type, confidence, *_ = validate_xss(raw)

        real_vuln   = expected[name]
        detected    = found and xss_type not in ("XSS_SUSPICIOUS",)

        if real_vuln and detected:     tp += 1; label = "TP"
        elif not real_vuln and detected: fp += 1; label = "FP"
        elif real_vuln and not detected: fn += 1; label = "FN"
        else:                            tn += 1; label = "TN"

        results.append((name, real_vuln, detected, xss_type, confidence, label))

        if i % 50 == 0:
            print(f"  [{i}/{len(xss_cases)}] TP={tp} FP={fp} TN={tn} FN={fn}")

    total = tp + fp + tn + fn
    tpr   = tp / (tp + fn) * 100 if (tp + fn) else 0
    fpr   = fp / (fp + tn) * 100 if (fp + tn) else 0

    print("\n" + "="*50)
    print("OWASP Benchmark XSS 결과")
    print("="*50)
    print(f"  True Positive  (탐지O / 실제 취약): {tp}")
    print(f"  False Positive (탐지O / 실제 안전): {fp}")
    print(f"  True Negative  (탐지X / 실제 안전): {tn}")
    print(f"  False Negative (탐지X / 실제 취약): {fn}")
    print(f"  오류 (파싱 실패): {err}")
    print(f"\n  True Positive Rate  (TPR): {tpr:.1f}%")
    print(f"  False Positive Rate (FPR): {fpr:.1f}%")

    # FP 목록 출력
    fp_list = [(n, t, c) for n, rv, d, t, c, l in results if l == "FP"]
    if fp_list:
        print(f"\n  [FP 목록] {len(fp_list)}개")
        for n, t, c in fp_list[:10]:
            print(f"    {n}: {t}/{c}")
        if len(fp_list) > 10:
            print(f"    ... 외 {len(fp_list)-10}개")

    # FN 목록 출력
    fn_list = [(n, t, c) for n, rv, d, t, c, l in results if l == "FN"]
    if fn_list:
        print(f"\n  [FN 목록 (미탐)] {len(fn_list)}개")
        for n, t, c in fn_list[:10]:
            print(f"    {n}: {t}/{c}")
        if len(fn_list) > 10:
            print(f"    ... 외 {len(fn_list)-10}개")


if __name__ == "__main__":
    main()
