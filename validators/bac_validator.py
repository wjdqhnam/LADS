def validate_bac(test_result):
    """Broken Access Control 검증"""
    request_info = test_result.get("request_info", {})
    response = test_result.get("response", {})
    
    url = request_info.get("url", "").lower()
    role = request_info.get("role", "guest")
    status = response.get("status", 400)
    body = response.get("body", "").lower()

    if ("adm" in url or "wp-admin" in url) and role != "admin":
        if status == 200:
            if "login" not in body and "로그인" not in body:
                return True, f"BAC 성공 (권한 없는 '{role}' 계정으로 관리자 페이지 접근)"
    
    return False, "안전함 (권한 통제 정상 작동)"