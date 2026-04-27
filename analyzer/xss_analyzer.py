# 그누보드 필터링 방어막 우회 체크 리스트
XSS_BYPASS_KEYWORDS = [
    "onerror=", "onload=", "ontoggle=", 
    "javascript:", "eval(", "onmouseover=",
    "string.fromcharcode", "animation-name:"
]

def validate_xss(test_result):
    """XSS (Stored, Reflected 및 우회) 검증"""
    payload = test_result.get("payload", "").lower()
    response_body = test_result.get("response", {}).get("body", "").lower() 
    
    if not response_body:
        return False, "검증 불가 (응답 HTML 바디 데이터 누락됨)"

    # 1. 우회 키워드 생존 확인
    for keyword in XSS_BYPASS_KEYWORDS:
        if keyword in payload and keyword in response_body:
            return True, f"고도화된 XSS 성공 (우회 키워드 '{keyword}' 살아남음)"

    # 2. 일반 반사 확인
    if payload and payload in response_body:
        return True, "일반 XSS 성공 (페이로드 원본이 변형 없이 렌더링됨)"

    return False, "안전함 (XSS 필터링됨 / HTML 인코딩됨)"