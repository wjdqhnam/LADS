def validate_xss(test_result):
    """XSS (Stored, Reflected 및 우회) 검증"""
    payload = test_result.get("payload", "").lower()
    response_body = test_result.get("response", {}).get("body", "").lower()
    xss_context = test_result.get("xss_context", "unknown")
    
    if not response_body:
        return False, "검증 불가 (응답 데이터 누락)"

    # 1. HTML 인코딩 여부 우선 확인 (필터링됨)
    if "&lt;" in response_body and (payload.startswith("<") or "onclick" in payload):
         return False, "안전함 (페이로드가 HTML 인코딩됨)"

    # 2. 페이로드 생존 확인 (scanner.py의 XSS_MARKERS 개념 적용)
    if payload in response_body:
        return True, f"XSS 성공 (컨텍스트: {xss_context}, 페이로드 반사 확인)"

    # 3. 부분 키워드 실행 가능성 확인
    critical_keywords = ["onerror=", "onload=", "eval(", "<svg"]
    for kw in critical_keywords:
        if kw in payload and kw in response_body:
            return True, f"XSS 성공 (위험 키워드 '{kw}' 실행 가능 환경)"

    return False, "안전함 (XSS 필터링됨)"