#!/usr/bin/env python3
# =====================================================
# OWASP ZAP 掃描結果比對工具
# =====================================================
# 比對 vulnerable 和 secure 版本的掃描結果
# 分析哪些漏洞已修復、哪些仍存在
# =====================================================

import json
import os
import sys
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
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'

# 風險等級對應
RISK_LEVELS = {
    '3': ('High', Colors.RED),
    '2': ('Medium', Colors.YELLOW),
    '1': ('Low', Colors.BLUE),
    '0': ('Informational', Colors.CYAN)
}

# OWASP Top 10 2021 對應 (根據 CWE)
OWASP_MAPPING = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable Components',
    'A07': 'Auth Failures',
    'A08': 'Data Integrity Failures',
    'A09': 'Logging Failures',
    'A10': 'SSRF'
}


def load_report(filepath: str) -> dict:
    """載入 ZAP JSON 報告"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] 找不到報告: {filepath}{Colors.NC}")
        return None
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}[!] JSON 解析錯誤: {e}{Colors.NC}")
        return None


def extract_alerts(report: dict) -> list:
    """從報告中提取所有警告"""
    alerts = []
    sites = report.get('site', [])
    for site in sites:
        site_alerts = site.get('alerts', [])
        for alert in site_alerts:
            alerts.append({
                'name': alert.get('name', 'Unknown'),
                'riskcode': alert.get('riskcode', '0'),
                'confidence': alert.get('confidence', '0'),
                'count': int(alert.get('count', 1)),
                'cweid': alert.get('cweid', ''),
                'wascid': alert.get('wascid', ''),
                'description': alert.get('desc', ''),
                'solution': alert.get('solution', ''),
                'instances': alert.get('instances', [])
            })
    return alerts


def count_by_risk(alerts: list) -> dict:
    """統計各風險等級數量"""
    counts = {'3': 0, '2': 0, '1': 0, '0': 0}
    for alert in alerts:
        risk = alert['riskcode']
        if risk in counts:
            counts[risk] += 1
    return counts


def print_header(text: str):
    """印出標題"""
    print()
    print(f"{Colors.CYAN}{'═' * 65}{Colors.NC}")
    print(f"{Colors.CYAN}  {text}{Colors.NC}")
    print(f"{Colors.CYAN}{'═' * 65}{Colors.NC}")
    print()


def print_risk_table(vuln_counts: dict, secure_counts: dict):
    """印出風險等級比較表"""
    print(f"{Colors.BOLD}{'Risk Level':<20} {'Vulnerable':<15} {'Secure':<15} {'Diff':<10}{Colors.NC}")
    print("-" * 60)
    
    total_vuln = 0
    total_secure = 0
    
    for code in ['3', '2', '1', '0']:
        level_name, color = RISK_LEVELS[code]
        vuln = vuln_counts.get(code, 0)
        secure = secure_counts.get(code, 0)
        diff = vuln - secure
        total_vuln += vuln
        total_secure += secure
        
        diff_str = f"{diff:+d}" if diff != 0 else "0"
        diff_color = Colors.GREEN if diff > 0 else (Colors.RED if diff < 0 else Colors.NC)
        
        print(f"{color}{level_name:<20}{Colors.NC} {vuln:<15} {secure:<15} {diff_color}{diff_str:<10}{Colors.NC}")
    
    print("-" * 60)
    total_diff = total_vuln - total_secure
    diff_str = f"{total_diff:+d}" if total_diff != 0 else "0"
    print(f"{Colors.BOLD}{'Total':<20} {total_vuln:<15} {total_secure:<15} {diff_str:<10}{Colors.NC}")


def print_fixed_vulnerabilities(vuln_alerts: list, secure_alerts: list):
    """印出已修復的漏洞"""
    secure_names = {a['name'] for a in secure_alerts}
    fixed = [a for a in vuln_alerts if a['name'] not in secure_names]
    
    if not fixed:
        print(f"{Colors.YELLOW}沒有發現已修復的漏洞 (可能是掃描覆蓋率不同){Colors.NC}")
        return
    
    # 按風險等級排序
    fixed.sort(key=lambda x: x['riskcode'], reverse=True)
    
    print(f"{Colors.GREEN}以下漏洞在 Secure 版本中未發現 (可能已修復):{Colors.NC}")
    print()
    
    for alert in fixed:
        risk_name, color = RISK_LEVELS.get(alert['riskcode'], ('Unknown', Colors.NC))
        print(f"  {color}[{risk_name}]{Colors.NC} {alert['name']}")
        if alert['cweid']:
            print(f"           CWE-{alert['cweid']}")


def print_remaining_vulnerabilities(vuln_alerts: list, secure_alerts: list):
    """印出仍存在的漏洞"""
    secure_names = {a['name'] for a in secure_alerts}
    remaining = [a for a in vuln_alerts if a['name'] in secure_names]
    
    if not remaining:
        print(f"{Colors.GREEN}太棒了！所有漏洞都已修復！{Colors.NC}")
        return
    
    # 按風險等級排序
    remaining.sort(key=lambda x: x['riskcode'], reverse=True)
    
    print(f"{Colors.YELLOW}以下漏洞在兩個版本中都存在:{Colors.NC}")
    print()
    
    for alert in remaining:
        risk_name, color = RISK_LEVELS.get(alert['riskcode'], ('Unknown', Colors.NC))
        print(f"  {color}[{risk_name}]{Colors.NC} {alert['name']}")


def print_new_in_secure(vuln_alerts: list, secure_alerts: list):
    """印出 Secure 版本新增的問題"""
    vuln_names = {a['name'] for a in vuln_alerts}
    new_alerts = [a for a in secure_alerts if a['name'] not in vuln_names]
    
    if not new_alerts:
        return
    
    print(f"{Colors.MAGENTA}以下問題只在 Secure 版本發現 (可能是誤報或新問題):{Colors.NC}")
    print()
    
    for alert in new_alerts:
        risk_name, color = RISK_LEVELS.get(alert['riskcode'], ('Unknown', Colors.NC))
        print(f"  {color}[{risk_name}]{Colors.NC} {alert['name']}")


def print_top_vulnerabilities(alerts: list, title: str, limit: int = 10):
    """印出最嚴重的漏洞"""
    # 按風險等級和出現次數排序
    sorted_alerts = sorted(alerts, key=lambda x: (x['riskcode'], x['count']), reverse=True)
    
    print(f"{Colors.BOLD}{title} (Top {limit}):{Colors.NC}")
    print()
    
    for i, alert in enumerate(sorted_alerts[:limit], 1):
        risk_name, color = RISK_LEVELS.get(alert['riskcode'], ('Unknown', Colors.NC))
        count = alert['count']
        print(f"  {i:2}. {color}[{risk_name}]{Colors.NC} {alert['name']} ({count} instances)")


def print_owasp_coverage(alerts: list):
    """分析 OWASP Top 10 覆蓋情況"""
    # 簡化的 CWE 到 OWASP 對應
    cwe_to_owasp = {
        # A01: Broken Access Control
        '22': 'A01', '23': 'A01', '35': 'A01', '59': 'A01',
        '200': 'A01', '201': 'A01', '219': 'A01', '264': 'A01',
        '275': 'A01', '276': 'A01', '284': 'A01', '285': 'A01',
        '352': 'A01', '359': 'A01', '377': 'A01', '402': 'A01',
        '425': 'A01', '441': 'A01', '497': 'A01', '538': 'A01',
        '540': 'A01', '548': 'A01', '552': 'A01', '566': 'A01',
        '601': 'A01', '639': 'A01', '651': 'A01', '668': 'A01',
        '706': 'A01', '862': 'A01', '863': 'A01', '913': 'A01',
        '922': 'A01', '1275': 'A01',
        # A02: Cryptographic Failures
        '261': 'A02', '296': 'A02', '310': 'A02', '319': 'A02',
        '321': 'A02', '322': 'A02', '323': 'A02', '324': 'A02',
        '325': 'A02', '326': 'A02', '327': 'A02', '328': 'A02',
        '329': 'A02', '330': 'A02', '331': 'A02', '335': 'A02',
        '336': 'A02', '337': 'A02', '338': 'A02', '340': 'A02',
        '347': 'A02', '523': 'A02', '720': 'A02', '757': 'A02',
        '759': 'A02', '760': 'A02', '780': 'A02', '818': 'A02',
        '916': 'A02',
        # A03: Injection
        '20': 'A03', '74': 'A03', '75': 'A03', '77': 'A03',
        '78': 'A03', '79': 'A03', '80': 'A03', '83': 'A03',
        '87': 'A03', '88': 'A03', '89': 'A03', '90': 'A03',
        '91': 'A03', '93': 'A03', '94': 'A03', '95': 'A03',
        '96': 'A03', '97': 'A03', '98': 'A03', '99': 'A03',
        '100': 'A03', '113': 'A03', '116': 'A03', '138': 'A03',
        '184': 'A03', '470': 'A03', '471': 'A03', '564': 'A03',
        '610': 'A03', '643': 'A03', '644': 'A03', '652': 'A03',
        '917': 'A03',
        # A05: Security Misconfiguration
        '2': 'A05', '11': 'A05', '13': 'A05', '15': 'A05',
        '16': 'A05', '260': 'A05', '315': 'A05', '520': 'A05',
        '526': 'A05', '537': 'A05', '541': 'A05', '547': 'A05',
        '611': 'A05', '614': 'A05', '756': 'A05', '776': 'A05',
        '942': 'A05', '1004': 'A05', '1032': 'A05', '1174': 'A05',
        # A07: Auth Failures
        '255': 'A07', '256': 'A07', '257': 'A07', '258': 'A07',
        '262': 'A07', '263': 'A07', '287': 'A07', '288': 'A07',
        '290': 'A07', '294': 'A07', '295': 'A07', '297': 'A07',
        '300': 'A07', '302': 'A07', '304': 'A07', '306': 'A07',
        '307': 'A07', '346': 'A07', '384': 'A07', '521': 'A07',
        '613': 'A07', '620': 'A07', '640': 'A07', '798': 'A07',
        '940': 'A07', '1216': 'A07',
        # A10: SSRF
        '918': 'A10',
    }
    
    found_categories = defaultdict(list)
    
    for alert in alerts:
        cweid = alert.get('cweid', '')
        if cweid in cwe_to_owasp:
            category = cwe_to_owasp[cweid]
            found_categories[category].append(alert['name'])
    
    print(f"{Colors.BOLD}OWASP Top 10 2021 覆蓋情況:{Colors.NC}")
    print()
    
    for cat_id in ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']:
        cat_name = OWASP_MAPPING.get(cat_id, 'Unknown')
        alerts_found = found_categories.get(cat_id, [])
        
        if alerts_found:
            print(f"  {Colors.GREEN}✓{Colors.NC} {cat_id}: {cat_name} ({len(alerts_found)} issues)")
        else:
            print(f"  {Colors.RED}✗{Colors.NC} {cat_id}: {cat_name}")


def main():
    # 報告目錄
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    reports_dir = project_root / 'zap-reports'
    
    vuln_report_path = reports_dir / 'vulnerable.json'
    secure_report_path = reports_dir / 'secure.json'
    
    # 載入報告
    vuln_report = load_report(str(vuln_report_path))
    secure_report = load_report(str(secure_report_path))
    
    if not vuln_report or not secure_report:
        print(f"\n{Colors.YELLOW}請先執行掃描:{Colors.NC}")
        print(f"  ./scripts/zap-scan.sh both")
        sys.exit(1)
    
    # 提取警告
    vuln_alerts = extract_alerts(vuln_report)
    secure_alerts = extract_alerts(secure_report)
    
    # 統計
    vuln_counts = count_by_risk(vuln_alerts)
    secure_counts = count_by_risk(secure_alerts)
    
    # 印出結果
    print_header("ZAP 掃描結果比對分析")
    
    print(f"{Colors.BOLD}📊 風險等級統計{Colors.NC}")
    print()
    print_risk_table(vuln_counts, secure_counts)
    
    print_header("🔧 已修復的漏洞")
    print_fixed_vulnerabilities(vuln_alerts, secure_alerts)
    
    print_header("⚠️  仍存在的漏洞")
    print_remaining_vulnerabilities(vuln_alerts, secure_alerts)
    
    new_in_secure = [a for a in secure_alerts if a['name'] not in {x['name'] for x in vuln_alerts}]
    if new_in_secure:
        print_header("❓ Secure 版本新發現")
        print_new_in_secure(vuln_alerts, secure_alerts)
    
    print_header("🔝 Vulnerable 版本最嚴重漏洞")
    print_top_vulnerabilities(vuln_alerts, "風險最高的漏洞", 10)
    
    print_header("📋 OWASP Top 10 覆蓋分析")
    print_owasp_coverage(vuln_alerts)
    
    # 總結
    print_header("📈 總結")
    total_vuln = sum(vuln_counts.values())
    total_secure = sum(secure_counts.values())
    fixed_count = len([a for a in vuln_alerts if a['name'] not in {x['name'] for x in secure_alerts}])
    
    print(f"  • Vulnerable 版本發現 {Colors.RED}{total_vuln}{Colors.NC} 個問題")
    print(f"  • Secure 版本發現 {Colors.GREEN}{total_secure}{Colors.NC} 個問題")
    print(f"  • 可能已修復 {Colors.GREEN}{fixed_count}{Colors.NC} 個問題")
    print()
    
    if fixed_count > 0:
        reduction = (fixed_count / total_vuln * 100) if total_vuln > 0 else 0
        print(f"  {Colors.GREEN}✓ 安全改善率: {reduction:.1f}%{Colors.NC}")
    
    print()
    print(f"{Colors.CYAN}詳細報告請查看:{Colors.NC}")
    print(f"  • {reports_dir}/vulnerable.html")
    print(f"  • {reports_dir}/secure.html")
    print()


if __name__ == '__main__':
    main()
