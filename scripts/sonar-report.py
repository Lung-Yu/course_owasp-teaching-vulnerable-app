#!/usr/bin/env python3
# =====================================================
# OWASP SonarQube 報告產生工具
# =====================================================
# 從 SonarQube API 取得分析結果並產生 HTML/JSON 報告
# 比對 backend-vulnerable 和 backend-secure 的差異
# =====================================================

import json
import os
import sys
import urllib.request
import urllib.error
import base64
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# 顏色定義
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'

# 設定檔路徑
SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR / '.sonar-config'

# SonarQube 設定（從設定檔或環境變數載入）
def load_config():
    config = {}
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return {
        'url': config.get('sonar_url', os.environ.get('SONAR_URL', 'http://localhost:9000')),
        'token': config.get('token', os.environ.get('SONAR_TOKEN', '')),
        'user': os.environ.get('SONAR_USER', 'admin'),
        'password': os.environ.get('SONAR_PASSWORD', 'admin')
    }

CONFIG = load_config()
SONAR_URL = CONFIG['url']
PROJECT_KEY = 'owasp-demo'

# 模組目錄對應
MODULES = ['backend-vulnerable', 'backend-secure', 'backend-log4shell', 'common']

# 嚴重度對應
SEVERITY_ORDER = {'BLOCKER': 5, 'CRITICAL': 4, 'MAJOR': 3, 'MINOR': 2, 'INFO': 1}

# OWASP Top 10 CWE 對應
OWASP_CWE_MAP = {
    'A01': ['22', '23', '35', '59', '200', '201', '219', '264', '275', '276', '284', '285', '352', '359', '377', '402', '425', '441', '497', '538', '540', '548', '552', '566', '601', '639', '651', '668', '706', '862', '863', '913', '922', '1275'],
    'A02': ['261', '296', '310', '319', '321', '322', '323', '324', '325', '326', '327', '328', '329', '330', '331', '335', '336', '337', '338', '340', '347', '523', '720', '757', '759', '760', '780', '818', '916'],
    'A03': ['20', '74', '75', '77', '78', '79', '80', '83', '87', '88', '89', '90', '91', '93', '94', '95', '96', '97', '98', '99', '100', '113', '116', '138', '184', '470', '471', '564', '610', '643', '644', '652', '917'],
    'A05': ['2', '11', '13', '15', '16', '260', '315', '520', '526', '537', '541', '547', '611', '614', '756', '776', '942', '1004', '1032', '1174'],
    'A07': ['255', '256', '257', '258', '262', '263', '287', '288', '290', '294', '295', '297', '300', '302', '304', '306', '307', '346', '384', '521', '613', '620', '640', '798', '940', '1216'],
    'A08': ['502', '829', '830', '913', '915'],
    'A09': ['117', '223', '532', '778'],
    'A10': ['918']
}

OWASP_NAMES = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A05': 'Security Misconfiguration',
    'A07': 'Auth Failures',
    'A08': 'Data Integrity Failures',
    'A09': 'Logging Failures',
    'A10': 'SSRF',
    'Other': 'Other Issues'
}


def api_request(endpoint: str, params: dict = None) -> tuple:
    """發送 SonarQube API 請求，回傳 (success, data)"""
    url = f"{SONAR_URL}/api/{endpoint}"
    if params:
        query_string = '&'.join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query_string}"
    
    req = urllib.request.Request(url)
    
    # 認證
    if CONFIG['token']:
        auth_header = base64.b64encode(f"{CONFIG['token']}:".encode()).decode()
    else:
        auth_header = base64.b64encode(f"{CONFIG['user']}:{CONFIG['password']}".encode()).decode()
    req.add_header('Authorization', f'Basic {auth_header}')
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return True, json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return False, {'status': e.code}
    except Exception as e:
        return False, {'error': str(e)}


def get_all_issues() -> list:
    """取得專案的所有問題"""
    all_issues = []
    page = 1
    page_size = 500
    
    while True:
        success, data = api_request('issues/search', {
            'componentKeys': PROJECT_KEY,
            'ps': page_size,
            'p': page,
            'resolved': 'false'
        })
        
        if not success:
            break
            
        issues = data.get('issues', [])
        all_issues.extend(issues)
        
        total = data.get('total', 0)
        if page * page_size >= total:
            break
        page += 1
    
    return all_issues


def filter_issues_by_module(issues: list, module: str) -> list:
    """按模組過濾 issues"""
    return [i for i in issues if module in i.get('component', '')]


def count_by_severity(issues: list) -> dict:
    """統計各嚴重度數量"""
    counts = defaultdict(int)
    for issue in issues:
        severity = issue.get('severity', 'INFO')
        counts[severity] += 1
    return dict(counts)


def count_by_type(issues: list) -> dict:
    """統計各類型數量"""
    counts = defaultdict(int)
    for issue in issues:
        issue_type = issue.get('type', 'UNKNOWN')
        counts[issue_type] += 1
    return dict(counts)


def categorize_by_owasp(issues: list) -> dict:
    """按 OWASP Top 10 分類"""
    categories = defaultdict(list)
    
    for issue in issues:
        tags = issue.get('tags', [])
        cwe = ''
        for tag in tags:
            if tag.startswith('cwe-'):
                cwe = tag.replace('cwe-', '')
                break
        
        matched = False
        for owasp_cat, cwes in OWASP_CWE_MAP.items():
            if cwe in cwes:
                categories[owasp_cat].append(issue)
                matched = True
                break
        
        if not matched:
            categories['Other'].append(issue)
    
    return dict(categories)


def generate_html_report(module_name: str, issues: list, output_path: str):
    """產生 HTML 報告"""
    severity_counts = count_by_severity(issues)
    type_counts = count_by_type(issues)
    vulnerabilities = [i for i in issues if i.get('type') == 'VULNERABILITY']
    owasp_categories = categorize_by_owasp(vulnerabilities)
    
    total_vulns = len(vulnerabilities)
    total_bugs = type_counts.get('BUG', 0)
    total_smells = type_counts.get('CODE_SMELL', 0)
    
    html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SonarQube 分析報告 - {module_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; margin-bottom: 30px; border-radius: 10px; }}
        header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }}
        .summary-card h3 {{ font-size: 2.5em; margin-bottom: 5px; }}
        .summary-card.critical h3 {{ color: #dc3545; }}
        .summary-card.warning h3 {{ color: #ffc107; }}
        .summary-card.info h3 {{ color: #17a2b8; }}
        section {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        section h2 {{ color: #333; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #eee; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .severity {{ padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 500; }}
        .severity.blocker, .severity.critical {{ background: #ffeaea; color: #dc3545; }}
        .severity.major {{ background: #fff3cd; color: #856404; }}
        .severity.minor {{ background: #cce5ff; color: #004085; }}
        .severity.info {{ background: #e2e3e5; color: #383d41; }}
        .owasp-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        .owasp-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #667eea; }}
        .owasp-card h4 {{ margin-bottom: 5px; }}
        .owasp-card .count {{ font-size: 1.5em; font-weight: bold; color: #667eea; }}
        .issue-list {{ max-height: 500px; overflow-y: auto; }}
        footer {{ text-align: center; padding: 20px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 SonarQube 分析報告</h1>
            <p>模組: {module_name} | 產生時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>{total_vulns}</h3>
                <p>安全漏洞</p>
            </div>
            <div class="summary-card warning">
                <h3>{total_bugs}</h3>
                <p>程式錯誤</p>
            </div>
            <div class="summary-card info">
                <h3>{total_smells}</h3>
                <p>程式碼異味</p>
            </div>
            <div class="summary-card">
                <h3>{len(issues)}</h3>
                <p>總問題數</p>
            </div>
        </div>
        
        <section>
            <h2>🔐 OWASP Top 10 分類</h2>
            <div class="owasp-grid">
"""
    
    for cat_id in ['A01', 'A02', 'A03', 'A05', 'A07', 'A08', 'A09', 'A10', 'Other']:
        issues_in_cat = owasp_categories.get(cat_id, [])
        cat_name = OWASP_NAMES.get(cat_id, cat_id)
        html += f"""
                <div class="owasp-card">
                    <h4>{cat_id}: {cat_name}</h4>
                    <div class="count">{len(issues_in_cat)}</div>
                </div>
"""
    
    html += """
            </div>
        </section>
        
        <section>
            <h2>🐛 嚴重度統計</h2>
            <table>
                <thead>
                    <tr><th>嚴重度</th><th>數量</th></tr>
                </thead>
                <tbody>
"""
    
    for sev in ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']:
        count = severity_counts.get(sev, 0)
        html += f"""
                    <tr>
                        <td><span class="severity {sev.lower()}">{sev}</span></td>
                        <td>{count}</td>
                    </tr>
"""
    
    html += """
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>📋 問題列表 (Top 100)</h2>
            <div class="issue-list">
                <table>
                    <thead>
                        <tr><th>嚴重度</th><th>類型</th><th>規則</th><th>訊息</th><th>檔案</th></tr>
                    </thead>
                    <tbody>
"""
    
    # 按嚴重度排序
    sorted_issues = sorted(issues, key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'INFO'), 0), reverse=True)
    
    for issue in sorted_issues[:100]:
        sev = issue.get('severity', 'INFO')
        itype = issue.get('type', 'UNKNOWN')
        rule = issue.get('rule', '').split(':')[-1]
        message = issue.get('message', '')[:80]
        component = issue.get('component', '').split(':')[-1]
        line = issue.get('line', '')
        file_loc = f"{component}:{line}" if line else component
        
        html += f"""
                        <tr>
                            <td><span class="severity {sev.lower()}">{sev}</span></td>
                            <td>{itype}</td>
                            <td>{rule}</td>
                            <td>{message}</td>
                            <td style="font-size:0.85em">{file_loc}</td>
                        </tr>
"""
    
    html += f"""
                    </tbody>
                </table>
            </div>
        </section>
        
        <footer>
            <p>由 OWASP Demo SonarQube 報告工具產生 | <a href="{SONAR_URL}/dashboard?id={PROJECT_KEY}">在 SonarQube 中查看完整報告</a></p>
        </footer>
    </div>
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_json_report(module_name: str, issues: list, output_path: str):
    """產生 JSON 報告"""
    report = {
        'module': module_name,
        'generated_at': datetime.now().isoformat(),
        'sonarqube_url': SONAR_URL,
        'severity_counts': count_by_severity(issues),
        'type_counts': count_by_type(issues),
        'owasp_categories': {k: len(v) for k, v in categorize_by_owasp(issues).items()},
        'total_issues': len(issues),
        'vulnerabilities': len([i for i in issues if i.get('type') == 'VULNERABILITY']),
        'issues': issues[:200]
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def generate_comparison_report(module_data: dict, output_path: str):
    """產生比對報告"""
    vuln_issues = module_data.get('backend-vulnerable', [])
    secure_issues = module_data.get('backend-secure', [])
    
    vuln_vulns = len([i for i in vuln_issues if i.get('type') == 'VULNERABILITY'])
    secure_vulns = len([i for i in secure_issues if i.get('type') == 'VULNERABILITY'])
    vuln_bugs = len([i for i in vuln_issues if i.get('type') == 'BUG'])
    secure_bugs = len([i for i in secure_issues if i.get('type') == 'BUG'])
    
    improvement = ((vuln_vulns - secure_vulns) / vuln_vulns * 100) if vuln_vulns > 0 else 0
    
    html = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SonarQube 比對報告 - Vulnerable vs Secure</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; margin-bottom: 30px; border-radius: 10px; text-align: center; }}
        .comparison {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card.vulnerable {{ border-top: 4px solid #dc3545; }}
        .card.secure {{ border-top: 4px solid #28a745; }}
        .card h2 {{ margin-bottom: 20px; }}
        .metric {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }}
        .improvement {{ text-align: center; background: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .improvement h2 {{ color: #28a745; font-size: 3em; }}
        section {{ background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; }}
        .diff-positive {{ color: #28a745; font-weight: bold; }}
        .diff-negative {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 SonarQube 比對報告</h1>
            <p>Vulnerable vs Secure | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="improvement">
            <p>安全改善率</p>
            <h2>{improvement:.1f}%</h2>
        </div>
        
        <div class="comparison">
            <div class="card vulnerable">
                <h2>🔓 Vulnerable 版本</h2>
                <div class="metric">
                    <span>安全漏洞</span>
                    <span>{vuln_vulns}</span>
                </div>
                <div class="metric">
                    <span>程式錯誤</span>
                    <span>{vuln_bugs}</span>
                </div>
                <div class="metric">
                    <span>總問題數</span>
                    <span>{len(vuln_issues)}</span>
                </div>
            </div>
            
            <div class="card secure">
                <h2>🔒 Secure 版本</h2>
                <div class="metric">
                    <span>安全漏洞</span>
                    <span>{secure_vulns}</span>
                </div>
                <div class="metric">
                    <span>程式錯誤</span>
                    <span>{secure_bugs}</span>
                </div>
                <div class="metric">
                    <span>總問題數</span>
                    <span>{len(secure_issues)}</span>
                </div>
            </div>
        </div>
        
        <section>
            <h2>📈 差異統計</h2>
            <table>
                <thead>
                    <tr><th>指標</th><th>Vulnerable</th><th>Secure</th><th>差異</th></tr>
                </thead>
                <tbody>
                    <tr>
                        <td>安全漏洞</td>
                        <td>{vuln_vulns}</td>
                        <td>{secure_vulns}</td>
                        <td class="{'diff-positive' if vuln_vulns > secure_vulns else 'diff-negative'}">{'+' if vuln_vulns > secure_vulns else ''}{vuln_vulns - secure_vulns}</td>
                    </tr>
                    <tr>
                        <td>程式錯誤</td>
                        <td>{vuln_bugs}</td>
                        <td>{secure_bugs}</td>
                        <td class="{'diff-positive' if vuln_bugs > secure_bugs else 'diff-negative'}">{'+' if vuln_bugs > secure_bugs else ''}{vuln_bugs - secure_bugs}</td>
                    </tr>
                    <tr>
                        <td>總問題數</td>
                        <td>{len(vuln_issues)}</td>
                        <td>{len(secure_issues)}</td>
                        <td class="{'diff-positive' if len(vuln_issues) > len(secure_issues) else 'diff-negative'}">{'+' if len(vuln_issues) > len(secure_issues) else ''}{len(vuln_issues) - len(secure_issues)}</td>
                    </tr>
                </tbody>
            </table>
        </section>
    </div>
</body>
</html>
"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def main():
    project_root = SCRIPT_DIR.parent
    reports_dir = project_root / 'sonar-reports'
    reports_dir.mkdir(exist_ok=True)
    
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print(f"{Colors.CYAN}  產生 SonarQube 分析報告{Colors.NC}")
    print(f"{Colors.CYAN}═══════════════════════════════════════════════════════════{Colors.NC}")
    print()
    
    # 檢查 SonarQube 連線
    print(f"{Colors.BLUE}[*] 連線到 SonarQube: {SONAR_URL}{Colors.NC}")
    success, data = api_request('system/status')
    if not success or data.get('status') != 'UP':
        print(f"{Colors.RED}[!] SonarQube 未運行或無法連線{Colors.NC}")
        sys.exit(1)
    
    print(f"{Colors.GREEN}[✓] SonarQube 連線成功{Colors.NC}")
    print()
    
    # 取得所有 issues
    print(f"{Colors.BLUE}[*] 取得分析結果...{Colors.NC}")
    all_issues = get_all_issues()
    print(f"{Colors.GREEN}[✓] 取得 {len(all_issues)} 個問題{Colors.NC}")
    print()
    
    if len(all_issues) == 0:
        print(f"{Colors.YELLOW}[!] 尚無分析結果，請先執行掃描: ./scripts/sonar-scan.sh scan{Colors.NC}")
        sys.exit(0)
    
    # 按模組過濾並產生報告
    module_data = {}
    
    for module in MODULES:
        issues = filter_issues_by_module(all_issues, module)
        module_data[module] = issues
        
        if len(issues) == 0:
            print(f"{Colors.YELLOW}[*] {module}: 無問題{Colors.NC}")
            continue
        
        html_path = reports_dir / f"{module}-report.html"
        json_path = reports_dir / f"{module}-report.json"
        
        generate_html_report(module, issues, str(html_path))
        generate_json_report(module, issues, str(json_path))
        
        vulns = len([i for i in issues if i.get('type') == 'VULNERABILITY'])
        print(f"{Colors.GREEN}[✓] {module}: {len(issues)} issues ({vulns} vulnerabilities){Colors.NC}")
        print(f"    HTML: {html_path}")
    
    print()
    
    # 產生比對報告
    if module_data.get('backend-vulnerable') and module_data.get('backend-secure'):
        print(f"{Colors.MAGENTA}[*] 產生比對報告...{Colors.NC}")
        comparison_path = reports_dir / "comparison-report.html"
        generate_comparison_report(module_data, str(comparison_path))
        print(f"{Colors.GREEN}[✓] 比對報告: {comparison_path}{Colors.NC}")
    
    print()
    print(f"{Colors.GREEN}[✓] 報告產生完成！{Colors.NC}")
    print(f"{Colors.BLUE}[*] 報告目錄: {reports_dir}{Colors.NC}")


if __name__ == '__main__':
    main()
