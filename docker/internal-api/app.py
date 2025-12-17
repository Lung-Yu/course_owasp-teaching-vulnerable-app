from flask import Flask, jsonify
import os

app = Flask(__name__)

# 模擬內部敏感資料
SECRETS = {
    "database": {
        "host": "postgres",
        "port": 5432,
        "username": "postgres",
        "password": "SuperSecretDBPassword123!"
    },
    "api_keys": {
        "stripe": "sk_live_xxxxxxxxxxxxxxxxxxxxx",
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "jwt_secret": "your-super-secret-jwt-key-that-should-never-be-exposed",
    "admin_credentials": {
        "username": "superadmin",
        "password": "Admin@123456"
    }
}

FLAG = "FLAG{ssrf_internal_service_accessed}"


@app.route('/')
def index():
    return jsonify({
        "service": "Internal API",
        "status": "running",
        "warning": "This service should NOT be accessible from outside!"
    })


@app.route('/health')
def health():
    return jsonify({"status": "healthy"})


@app.route('/secrets')
def get_secrets():
    """
    ⚠️ 這是一個敏感端點，不應該被外部存取
    透過 SSRF 攻擊可以存取這個端點
    """
    return jsonify({
        "secrets": SECRETS,
        "flag": FLAG,
        "message": "🚨 如果你看到這個訊息，代表 SSRF 攻擊成功！"
    })


@app.route('/admin/config')
def admin_config():
    """
    ⚠️ 管理員設定端點
    """
    return jsonify({
        "config": {
            "debug_mode": True,
            "log_level": "DEBUG",
            "max_connections": 100,
            "cache_enabled": True
        },
        "flag": FLAG,
        "internal_endpoints": [
            "/secrets",
            "/admin/config",
            "/admin/users",
            "/metrics"
        ]
    })


@app.route('/admin/users')
def admin_users():
    """
    ⚠️ 內部使用者管理端點
    """
    return jsonify({
        "users": [
            {"id": 1, "username": "admin", "role": "SUPER_ADMIN", "api_key": "admin-key-12345"},
            {"id": 2, "username": "developer", "role": "DEVELOPER", "api_key": "dev-key-67890"},
            {"id": 3, "username": "support", "role": "SUPPORT", "api_key": "support-key-11111"}
        ],
        "flag": FLAG
    })


@app.route('/metrics')
def metrics():
    """
    ⚠️ 系統指標端點
    """
    return jsonify({
        "cpu_usage": 45.2,
        "memory_usage": 68.5,
        "disk_usage": 32.1,
        "active_connections": 127,
        "requests_per_second": 523,
        "error_rate": 0.02,
        "internal_ips": [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3"
        ],
        "flag": FLAG
    })


@app.route('/export/all')
def export_all():
    """
    ⚠️ 匯出所有資料
    """
    return jsonify({
        "secrets": SECRETS,
        "users": [
            {"id": 1, "username": "admin", "password_hash": "$2a$10$xxxxx"},
            {"id": 2, "username": "user", "password_hash": "$2a$10$yyyyy"}
        ],
        "config": {
            "debug_mode": True,
            "database_url": "postgresql://postgres:SuperSecretDBPassword123!@postgres:5432/owasp_demo"
        },
        "flag": FLAG,
        "message": "Complete data export - this should never be accessible externally!"
    })


@app.route('/cloud-metadata')
def cloud_metadata():
    """
    模擬雲端 metadata 端點（如 AWS EC2）
    真實環境中這通常在 169.254.169.254
    """
    return jsonify({
        "ami-id": "ami-0abcdef1234567890",
        "instance-id": "i-0abcdef1234567890",
        "instance-type": "t2.micro",
        "local-ipv4": "10.0.0.100",
        "public-ipv4": "203.0.113.25",
        "iam": {
            "security-credentials": {
                "role-name": "ec2-ssrf-demo-role",
                "access_key_id": "ASIAXXX",
                "secret_access_key": "SECRETXXX",
                "token": "FwoGZXIvYXdzEBYaDKrDC..."
            }
        },
        "flag": FLAG
    })


@app.route('/redirect')
def open_redirect():
    """
    ⚠️ 開放重定向端點 - 用於 SSRF Bypass 測試
    攻擊者可利用此端點繞過 URL 白名單檢查
    
    範例：
    - /redirect?url=http://internal-api:8080/secrets
    - 如果白名單允許 internal-api，可透過重定向存取任意內部服務
    """
    from flask import redirect, request
    target_url = request.args.get('url', '/')
    
    # ⚠️ 漏洞：無驗證直接重定向
    return redirect(target_url)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
