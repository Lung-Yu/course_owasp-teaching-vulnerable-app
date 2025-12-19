#!/usr/bin/env python3
"""
A05:2021 - Security Misconfiguration
安全標頭檢查工具

此腳本檢查 HTTP 回應中的安全標頭：
1. X-Content-Type-Options
2. X-Frame-Options
3. X-XSS-Protection
4. Content-Security-Policy
5. Strict-Transport-Security
6. Referrer-Policy
7. Permissions-Policy
8. Cache-Control

CWE-693: Protection Mechanism Failure
"""

import requests
import argparse

# ANSI 顏色
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


def print_banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════════╗
║  A05 - Security Headers Analysis Tool                        ║
║  HTTP 安全標頭檢查工具                                         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


# 安全標頭配置
SECURITY_HEADERS = {
    "X-Content-Type-Options": {
        "description": "防止 MIME 類型嗅探",
        "recommended": "nosniff",
        "risk": "攻擊者可能利用 MIME 嗅探執行 XSS 攻擊",
        "severity": "中",
    },
    "X-Frame-Options": {
        "description": "防止點擊劫持",
        "recommended": ["DENY", "SAMEORIGIN"],
        "risk": "網站可能被嵌入惡意 iframe 進行點擊劫持",
        "severity": "中",
    },
    "X-XSS-Protection": {
        "description": "啟用 XSS 過濾器（舊版瀏覽器）",
        "recommended": "1; mode=block",
        "risk": "舊版瀏覽器可能無法阻止反射型 XSS",
        "severity": "低",
    },
    "Content-Security-Policy": {
        "description": "限制資源載入來源",
        "recommended": "default-src 'self'",
        "risk": "可能遭受 XSS、資料注入等攻擊",
        "severity": "高",
    },
    "Strict-Transport-Security": {
        "description": "強制 HTTPS 連線",
        "recommended": "max-age=31536000; includeSubDomains",
        "risk": "可能遭受中間人攻擊、SSL 降級攻擊",
        "severity": "高",
    },
    "Referrer-Policy": {
        "description": "控制 Referer 資訊洩露",
        "recommended": ["strict-origin-when-cross-origin", "no-referrer", "same-origin"],
        "risk": "敏感資訊可能透過 Referer 標頭洩露",
        "severity": "低",
    },
    "Permissions-Policy": {
        "description": "限制瀏覽器功能",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "risk": "惡意腳本可能濫用瀏覽器功能",
        "severity": "低",
    },
    "Cache-Control": {
        "description": "控制快取行為",
        "recommended": "no-store",
        "risk": "敏感資料可能被快取",
        "severity": "中",
    },
}


def check_header(headers, header_name, config):
    """檢查單個標頭"""
    value = headers.get(header_name)
    
    if value is None:
        return {
            "status": "missing",
            "value": None,
            "message": f"缺少 {header_name} 標頭",
            "severity": config["severity"],
        }
    
    recommended = config["recommended"]
    
    # 檢查值是否符合建議
    if isinstance(recommended, list):
        is_valid = any(r.lower() in value.lower() for r in recommended)
    else:
        is_valid = recommended.lower() in value.lower()
    
    if is_valid:
        return {
            "status": "ok",
            "value": value,
            "message": f"{header_name} 已正確設定",
            "severity": None,
        }
    else:
        return {
            "status": "weak",
            "value": value,
            "message": f"{header_name} 設定不符合建議值",
            "severity": config["severity"],
        }


def analyze_headers(base_url, session, endpoint="/"):
    """分析 HTTP 回應標頭"""
    print(f"\n{BLUE}[*] 分析 {base_url}{endpoint} 的安全標頭...{RESET}")
    
    url = f"{base_url}{endpoint}"
    response = session.get(url, timeout=10)
    
    print(f"    狀態碼: {response.status_code}")
    print(f"\n{YELLOW}[*] 標頭分析結果:{RESET}\n")
    
    results = {}
    issues = []
    
    for header_name, config in SECURITY_HEADERS.items():
        result = check_header(response.headers, header_name, config)
        results[header_name] = result
        
        if result["status"] == "missing":
            severity_color = RED if config["severity"] == "高" else YELLOW
            print(f"  {RED}✗ {header_name}{RESET}")
            print(f"    {severity_color}狀態: 缺少{RESET}")
            print(f"    描述: {config['description']}")
            print(f"    風險: {config['risk']}")
            print(f"    嚴重性: {config['severity']}")
            print(f"    建議值: {config['recommended']}")
            print()
            issues.append((header_name, config["severity"], "missing"))
            
        elif result["status"] == "weak":
            print(f"  {YELLOW}⚠ {header_name}{RESET}")
            print(f"    狀態: 設定不安全")
            print(f"    當前值: {result['value']}")
            print(f"    建議值: {config['recommended']}")
            print()
            issues.append((header_name, config["severity"], "weak"))
            
        else:
            print(f"  {GREEN}✓ {header_name}{RESET}")
            print(f"    值: {result['value'][:60]}..." if len(result['value']) > 60 else f"    值: {result['value']}")
            print()
    
    return results, issues


def check_cors_headers(base_url, session):
    """檢查 CORS 配置"""
    print(f"\n{BLUE}[*] 檢查 CORS 配置...{RESET}")
    
    # 發送帶有 Origin 的請求
    headers = {"Origin": "https://evil.com"}
    url = f"{base_url}/api/products"
    
    try:
        response = session.get(url, headers=headers, timeout=10)
        
        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        
        print(f"\n  Origin: https://evil.com")
        print(f"  Access-Control-Allow-Origin: {acao}")
        print(f"  Access-Control-Allow-Credentials: {acac}")
        
        issues = []
        
        if acao == "*":
            print(f"\n  {RED}[!] 警告: CORS 允許所有來源 (*){RESET}")
            issues.append("wildcard_origin")
        elif acao == "https://evil.com":
            print(f"\n  {RED}[!] 警告: CORS 反射了任意 Origin！{RESET}")
            issues.append("origin_reflection")
            
            if acac and acac.lower() == "true":
                print(f"  {RED}[!] 嚴重: 同時允許憑證，可能導致帳號劫持！{RESET}")
                issues.append("credentials_with_reflection")
        else:
            print(f"\n  {GREEN}[+] CORS 配置看起來安全{RESET}")
        
        return issues
        
    except Exception as e:
        print(f"  {YELLOW}[?] 無法檢查 CORS: {e}{RESET}")
        return []


def check_cookies(base_url, session):
    """檢查 Cookie 安全屬性"""
    print(f"\n{BLUE}[*] 檢查 Cookie 安全屬性...{RESET}")
    
    # 嘗試登入以獲取 Cookie
    url = f"{base_url}/api/auth/login"
    data = {"username": "admin", "password": "admin123"}
    
    try:
        response = session.post(url, json=data, timeout=10)
        
        cookies = response.cookies
        set_cookie_headers = response.headers.get("Set-Cookie", "")
        
        if not cookies and not set_cookie_headers:
            print(f"  {YELLOW}[?] 未設定任何 Cookie{RESET}")
            return []
        
        issues = []
        
        # 解析 Set-Cookie 標頭
        if set_cookie_headers:
            print(f"\n  Set-Cookie: {set_cookie_headers[:100]}...")
            
            # 檢查安全屬性
            sc_lower = set_cookie_headers.lower()
            
            if "httponly" not in sc_lower:
                print(f"  {RED}[!] 缺少 HttpOnly 屬性{RESET}")
                issues.append("missing_httponly")
            else:
                print(f"  {GREEN}[+] 有 HttpOnly 屬性{RESET}")
            
            if "secure" not in sc_lower:
                print(f"  {RED}[!] 缺少 Secure 屬性{RESET}")
                issues.append("missing_secure")
            else:
                print(f"  {GREEN}[+] 有 Secure 屬性{RESET}")
            
            if "samesite" not in sc_lower:
                print(f"  {YELLOW}[!] 缺少 SameSite 屬性{RESET}")
                issues.append("missing_samesite")
            else:
                print(f"  {GREEN}[+] 有 SameSite 屬性{RESET}")
        
        return issues
        
    except Exception as e:
        print(f"  {YELLOW}[?] 無法檢查 Cookie: {e}{RESET}")
        return []


def compare_versions(vulnerable_url, secure_url, session):
    """比較安全版本與漏洞版本"""
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}[*] 比較兩個版本的安全標頭{RESET}")
    
    print(f"\n{RED}=== 漏洞版本 ({vulnerable_url}) ==={RESET}")
    vuln_results, vuln_issues = analyze_headers(vulnerable_url, session)
    
    print(f"\n{GREEN}=== 安全版本 ({secure_url}) ==={RESET}")
    sec_results, sec_issues = analyze_headers(secure_url, session)
    
    # 比較結果
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{YELLOW}[*] 比較總結:{RESET}")
    print(f"    漏洞版本問題: {len(vuln_issues)} 個")
    print(f"    安全版本問題: {len(sec_issues)} 個")
    
    # 顯示改善的項目
    improved = []
    for header_name in SECURITY_HEADERS:
        vuln_status = vuln_results.get(header_name, {}).get("status")
        sec_status = sec_results.get(header_name, {}).get("status")
        
        if vuln_status in ["missing", "weak"] and sec_status == "ok":
            improved.append(header_name)
    
    if improved:
        print(f"\n{GREEN}[+] 安全版本改善的項目:{RESET}")
        for header in improved:
            print(f"    - {header}")
    
    return vuln_issues, sec_issues


def main():
    parser = argparse.ArgumentParser(
        description="A05 - HTTP 安全標頭檢查",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例:
  %(prog)s                    # 檢查漏洞版本
  %(prog)s --compare          # 比較兩個版本
  %(prog)s --check-cors       # 額外檢查 CORS
  %(prog)s --check-cookies    # 額外檢查 Cookie
        """
    )
    parser.add_argument("--vulnerable-url", default="http://localhost:8081",
                        help="漏洞版本 URL")
    parser.add_argument("--secure-url", default="http://localhost:8082",
                        help="安全版本 URL")
    parser.add_argument("--compare", action="store_true",
                        help="比較安全版本與漏洞版本")
    parser.add_argument("--check-cors", action="store_true",
                        help="額外檢查 CORS 配置")
    parser.add_argument("--check-cookies", action="store_true",
                        help="額外檢查 Cookie 安全屬性")
    parser.add_argument("--endpoint", default="/",
                        help="要檢查的端點")
    
    args = parser.parse_args()
    
    print_banner()
    
    session = requests.Session()
    session.verify = False  # 忽略 SSL 驗證（測試用）
    
    # 禁用 SSL 警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    if args.compare:
        vuln_issues, sec_issues = compare_versions(
            args.vulnerable_url, args.secure_url, session
        )
    else:
        print(f"{YELLOW}[*] 目標: {args.vulnerable_url}{RESET}")
        results, issues = analyze_headers(args.vulnerable_url, session, args.endpoint)
    
    # 額外檢查
    if args.check_cors:
        check_cors_headers(args.vulnerable_url, session)
    
    if args.check_cookies:
        check_cookies(args.vulnerable_url, session)
    
    # 總結
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{YELLOW}[*] 防禦建議:{RESET}")
    print("    1. 添加 SecurityHeadersFilter 設定所有安全標頭")
    print("    2. 使用 Spring Security 的 headers() 配置")
    print("    3. 在 Web 伺服器層面設定標頭 (Nginx/Apache)")
    print("    4. 定期使用工具檢查安全標頭")
    print("    5. 參考 securityheaders.com 進行線上檢查")
    
    print(f"\n{YELLOW}[*] 相關資源:{RESET}")
    print("    - https://securityheaders.com/")
    print("    - https://owasp.org/www-project-secure-headers/")
    print("    - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers")


if __name__ == "__main__":
    main()
