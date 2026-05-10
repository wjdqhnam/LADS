def validate_bac(test_result):
    """Broken Access Control 검증"""
    request_info = test_result.get("request_info", {})
    response = test_result.get("response", {})

    url = request_info.get("url", "").lower()
    role = request_info.get("role", "guest")
    status = response.get("status", 0)
    body = response.get("body", "").lower()

    # 관리자 경로 접근 시도 확인
    admin_paths = ["/adm/", "/wp-admin", "/install/"]
    is_admin_path = any(path in url for path in admin_paths)

    if is_admin_path and role != "admin":
        # 1. 권한 없음에도 200 OK 응답
        if status == 200:
            # 로그인 페이지로 리다이렉트된 것이 아닌지 재확인
            login_indicators = ["login", "로그인", "auth", "접근 권한"]
            if not any(ind in body for ind in login_indicators):
                # 실제 관리자 페이지의 특징적인 키워드가 있는지 (예: '관리자', 'setup', 'config')
                admin_indicators = ["admin", "관리자", "회원관리", "설정", "dashboard"]
                if any(ind in body for ind in admin_indicators):
                    return True, f"BAC 성공 (비인가 계정 '{role}'으로 관리자 기능 접근)"

    return False, "안전함 (권한 통제 정상)"