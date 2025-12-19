-- =====================================================
-- 建立 SonarQube 資料庫
-- =====================================================
CREATE DATABASE sonarqube;
GRANT ALL PRIVILEGES ON DATABASE sonarqube TO postgres;

-- =====================================================
-- 建立表格結構
-- =====================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(50),
    phone VARCHAR(20),
    role VARCHAR(20) DEFAULT 'USER',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    stock INTEGER DEFAULT 0,
    category VARCHAR(100),
    image_url VARCHAR(500),
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    order_number VARCHAR(50) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    status VARCHAR(20) DEFAULT 'PENDING',
    total_amount DECIMAL(10,2) NOT NULL,
    shipping_address TEXT,
    note TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS order_items (
    id SERIAL PRIMARY KEY,
    order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    subtotal DECIMAL(10,2) NOT NULL
);

INSERT INTO users (username, password, email, full_name, phone, role, enabled, created_at)
VALUES 
    ('admin', 'admin123', 'admin@example.com', 'System Admin', '0912-345-678', 'ADMIN', true, NOW()),
    ('user', 'user123', 'user@example.com', 'Test User', '0923-456-789', 'USER', true, NOW()),
    ('alice', 'alice123', 'alice@example.com', 'Alice Wang', '0934-567-890', 'USER', true, NOW()),
    ('bob', 'bob123', 'bob@example.com', 'Bob Chen', '0945-678-901', 'USER', true, NOW()),
    ('vip', 'vip123', 'vip@example.com', 'VIP Customer', '0956-789-012', 'VIP', true, NOW()),
    ('manager', 'manager123', 'manager@example.com', 'Store Manager', '0967-890-123', 'MANAGER', true, NOW()),
    ('locked', 'locked123', 'locked@example.com', 'Locked User', '0978-901-234', 'USER', false, NOW()),
    ('guest', 'guest123', 'guest@example.com', 'Guest User', NULL, 'GUEST', true, NOW())
ON CONFLICT (username) DO NOTHING;

INSERT INTO products (name, description, price, stock, category, active, created_at)
VALUES 
    ('MacBook Pro 14', 'M3 Pro chip, 18GB RAM, 512GB SSD', 59900.00, 10, 'Electronics', true, NOW()),
    ('iPhone 15 Pro', 'A17 Pro chip, Titanium design', 36900.00, 25, 'Electronics', true, NOW()),
    ('AirPods Pro', 'Active noise cancellation', 7490.00, 30, 'Electronics', true, NOW()),
    ('iPad Air', 'M1 chip, 10.9 inch display', 19900.00, 15, 'Electronics', true, NOW()),
    ('Apple Watch', 'Series 9, GPS + Cellular', 14900.00, 20, 'Electronics', true, NOW()),
    ('Classic T-Shirt', '100% cotton, comfortable fit', 590.00, 100, 'Clothing', true, NOW()),
    ('Jeans', 'Classic straight cut', 1290.00, 50, 'Clothing', true, NOW()),
    ('Hoodie', 'Warm fleece lining', 1490.00, 40, 'Clothing', true, NOW()),
    ('Sneakers', 'Lightweight running shoes', 2990.00, 35, 'Clothing', true, NOW()),
    ('Programming Guide', 'Learn Python and JavaScript', 480.00, 200, 'Books', true, NOW()),
    ('Security Handbook', 'OWASP Top 10 vulnerabilities', 680.00, 150, 'Books', true, NOW()),
    ('Algorithm Book', 'Data structures and algorithms', 520.00, 180, 'Books', true, NOW()),
    ('Database Design', 'SQL and NoSQL fundamentals', 550.00, 120, 'Books', true, NOW()),
    ('Coffee Mug', 'Developer themed mug', 290.00, 500, 'Accessories', true, NOW()),
    ('Laptop Stand', 'Ergonomic aluminum stand', 1290.00, 60, 'Accessories', true, NOW()),
    ('Discontinued Item', 'No longer available', 999.00, 0, 'Other', false, NOW())
ON CONFLICT DO NOTHING;

INSERT INTO orders (order_number, user_id, status, total_amount, shipping_address, note, created_at, updated_at)
VALUES 
    ('ORD-00001', 1, 'DELIVERED', 96800.00, 'Taipei City, Xinyi District', 'Confidential order, Employee ID: A12345', NOW() - INTERVAL '30 days', NOW()),
    ('ORD-00002', 1, 'SHIPPED', 7490.00, 'Taipei City, Zhongzheng District', 'VIP priority, Card ending 8888', NOW() - INTERVAL '15 days', NOW()),
    ('ORD-00003', 1, 'PENDING', 19900.00, 'New Taipei City, Banqiao District', 'Gift wrap, Phone: 0912-345-678', NOW() - INTERVAL '3 days', NOW()),
    ('ORD-00004', 2, 'DELIVERED', 1880.00, 'Taichung City, Xitun District', NULL, NOW() - INTERVAL '25 days', NOW()),
    ('ORD-00005', 2, 'CONFIRMED', 36900.00, 'Taichung City, Beitun District', 'Color: Space Black', NOW() - INTERVAL '5 days', NOW()),
    ('ORD-00006', 3, 'DELIVERED', 59900.00, 'Kaohsiung City, Qianzhen District', 'Card: 4111-1111-1111-1234, 12 installments', NOW() - INTERVAL '20 days', NOW()),
    ('ORD-00007', 3, 'PENDING', 2780.00, 'Kaohsiung City, Lingya District', 'ID: A123456789', NOW() - INTERVAL '2 days', NOW()),
    ('ORD-00008', 4, 'CANCELLED', 1490.00, 'Tainan City, East District', 'Cancel reason: Wrong size', NOW() - INTERVAL '10 days', NOW()),
    ('ORD-00009', 4, 'SHIPPED', 680.00, 'Tainan City, West Central District', 'Tax ID: 12345678', NOW() - INTERVAL '7 days', NOW()),
    ('ORD-00010', 5, 'DELIVERED', 74800.00, 'Taipei City, Daan District', 'VIP exclusive discount applied', NOW() - INTERVAL '45 days', NOW()),
    ('ORD-00011', 5, 'PROCESSING', 14900.00, 'Taipei City, Daan District', NULL, NOW() - INTERVAL '1 day', NOW()),
    ('ORD-00012', 6, 'REFUNDED', 2990.00, 'Hsinchu City, East District', 'Defective item returned', NOW() - INTERVAL '60 days', NOW())
ON CONFLICT (order_number) DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 59900.00, 59900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00001' AND p.name = 'MacBook Pro 14'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 36900.00, 36900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00001' AND p.name = 'iPhone 15 Pro'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 7490.00, 7490.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00002' AND p.name = 'AirPods Pro'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 19900.00, 19900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00003' AND p.name = 'iPad Air'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 2, 590.00, 1180.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00004' AND p.name = 'Classic T-Shirt'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 680.00, 680.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00004' AND p.name = 'Security Handbook'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 36900.00, 36900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00005' AND p.name = 'iPhone 15 Pro'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 59900.00, 59900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00006' AND p.name = 'MacBook Pro 14'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 1490.00, 1490.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00007' AND p.name = 'Hoodie'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 1290.00, 1290.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00007' AND p.name = 'Jeans'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 1490.00, 1490.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00008' AND p.name = 'Hoodie'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 680.00, 680.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00009' AND p.name = 'Security Handbook'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 59900.00, 59900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00010' AND p.name = 'MacBook Pro 14'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 14900.00, 14900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00010' AND p.name = 'Apple Watch'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 14900.00, 14900.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00011' AND p.name = 'Apple Watch'
ON CONFLICT DO NOTHING;

INSERT INTO order_items (order_id, product_id, quantity, unit_price, subtotal)
SELECT o.id, p.id, 1, 2990.00, 2990.00
FROM orders o, products p 
WHERE o.order_number = 'ORD-00012' AND p.name = 'Sneakers'
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS coupons (
    id SERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(255),
    discount_type VARCHAR(20) NOT NULL,
    discount_value DECIMAL(10,2) NOT NULL,
    min_purchase DECIMAL(10,2) DEFAULT 0,
    max_discount DECIMAL(10,2),
    usage_limit INTEGER DEFAULT 1,
    used_count INTEGER DEFAULT 0,
    per_user_limit INTEGER DEFAULT 1,
    stackable BOOLEAN DEFAULT false,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coupon_usages (
    id SERIAL PRIMARY KEY,
    coupon_id INTEGER REFERENCES coupons(id),
    user_id INTEGER REFERENCES users(id),
    order_id INTEGER REFERENCES orders(id),
    used_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE REFERENCES users(id),
    balance DECIMAL(10,2) DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wallet_transactions (
    id SERIAL PRIMARY KEY,
    wallet_id INTEGER REFERENCES wallets(id),
    type VARCHAR(20) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    balance_after DECIMAL(10,2) NOT NULL,
    reference_id VARCHAR(100),
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS flash_sales (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    flash_price DECIMAL(10,2) NOT NULL,
    stock_limit INTEGER NOT NULL,
    sold_count INTEGER DEFAULT 0,
    per_user_limit INTEGER DEFAULT 1,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS flash_sale_purchases (
    id SERIAL PRIMARY KEY,
    flash_sale_id INTEGER REFERENCES flash_sales(id),
    user_id INTEGER REFERENCES users(id),
    quantity INTEGER NOT NULL,
    purchased_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO coupons (code, description, discount_type, discount_value, min_purchase, max_discount, usage_limit, per_user_limit, stackable, start_date, end_date, active)
VALUES 
    ('WELCOME10', 'New user 10% off', 'PERCENTAGE', 10.00, 100.00, 1000.00, 1000, 1, false, NOW() - INTERVAL '30 days', NOW() + INTERVAL '365 days', true),
    ('SAVE500', 'Save 500 on 3000+', 'FIXED_AMOUNT', 500.00, 3000.00, 500.00, 500, 1, false, NOW() - INTERVAL '30 days', NOW() + INTERVAL '30 days', true),
    ('UNLIMITED', 'Unlimited use coupon', 'PERCENTAGE', 20.00, 0, NULL, 999999, 999999, true, NOW() - INTERVAL '30 days', NOW() + INTERVAL '365 days', true),
    ('STACK100', 'Stackable 100 off', 'FIXED_AMOUNT', 100.00, 0, NULL, 999999, 999999, true, NOW() - INTERVAL '30 days', NOW() + INTERVAL '365 days', true),
    ('EXPIRED50', 'Expired 50% off', 'PERCENTAGE', 50.00, 0, NULL, 100, 1, false, NOW() - INTERVAL '60 days', NOW() - INTERVAL '30 days', true),
    ('FREE100', 'Free 100% off', 'PERCENTAGE', 100.00, 0, NULL, 10, 1, false, NOW() - INTERVAL '30 days', NOW() + INTERVAL '365 days', true),
    ('VIP90OFF', 'VIP 90% off', 'PERCENTAGE', 90.00, 0, NULL, 100, 10, false, NOW() - INTERVAL '30 days', NOW() + INTERVAL '365 days', true),
    ('SUMMER20', 'Summer sale 20% off', 'PERCENTAGE', 20.00, 500.00, 2000.00, 200, 2, false, NOW(), NOW() + INTERVAL '90 days', true),
    ('NEGATIVE', 'Negative discount test', 'FIXED_AMOUNT', -100.00, 0, NULL, 100, 1, false, NOW(), NOW() + INTERVAL '30 days', true)
ON CONFLICT (code) DO NOTHING;

INSERT INTO wallets (user_id, balance)
SELECT id, 
    CASE 
        WHEN username = 'admin' THEN 10000.00
        WHEN username = 'vip' THEN 50000.00
        WHEN username = 'locked' THEN 0.00
        ELSE 1000.00
    END
FROM users
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO flash_sales (product_id, flash_price, stock_limit, per_user_limit, start_time, end_time, active)
SELECT id, 29900.00, 5, 1, NOW(), NOW() + INTERVAL '7 days', true
FROM products WHERE name = 'MacBook Pro 14'
ON CONFLICT DO NOTHING;

INSERT INTO flash_sales (product_id, flash_price, stock_limit, per_user_limit, start_time, end_time, active)
SELECT id, 4990.00, 10, 2, NOW(), NOW() + INTERVAL '7 days', true
FROM products WHERE name = 'AirPods Pro'
ON CONFLICT DO NOTHING;

INSERT INTO flash_sales (product_id, flash_price, stock_limit, per_user_limit, start_time, end_time, active)
SELECT id, 9900.00, 3, 1, NOW(), NOW() + INTERVAL '3 days', true
FROM products WHERE name = 'Apple Watch'
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS deserialization_logs (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(100),
    class_name VARCHAR(500),
    payload_size INTEGER,
    payload_hash VARCHAR(64),
    source_ip VARCHAR(45),
    user_agent VARCHAR(500),
    blocked BOOLEAN DEFAULT false,
    block_reason VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS plugins (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    version VARCHAR(20) NOT NULL,
    description VARCHAR(500),
    download_url VARCHAR(500),
    sha256_hash VARCHAR(64),
    signature VARCHAR(1024),
    publisher VARCHAR(100),
    verified BOOLEAN DEFAULT false,
    installed_at TIMESTAMP DEFAULT NOW(),
    active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS signed_carts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    cart_data TEXT NOT NULL,
    hmac_signature VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS software_updates (
    id SERIAL PRIMARY KEY,
    component_name VARCHAR(100) NOT NULL,
    current_version VARCHAR(20),
    new_version VARCHAR(20),
    update_url VARCHAR(500),
    sha256_hash VARCHAR(64),
    signature VARCHAR(1024),
    verified BOOLEAN DEFAULT false,
    applied_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO plugins (name, version, description, download_url, sha256_hash, publisher, verified, active)
VALUES 
    ('payment-gateway', '1.0.0', 'Payment gateway plugin', 'http://trusted-repo.example.com/plugins/payment-gateway-1.0.0.jar', 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456', 'TrustedCorp', true, true),
    ('analytics', '2.1.0', 'Analytics tracking plugin', 'http://trusted-repo.example.com/plugins/analytics-2.1.0.jar', 'b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef12', 'AnalyticsCo', true, true),
    ('cache-manager', '1.5.2', 'Cache management plugin', 'http://trusted-repo.example.com/plugins/cache-manager-1.5.2.jar', 'c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890', 'CachePro', true, false),
    ('untrusted-plugin', '0.1.0', 'Untrusted plugin', 'http://evil.example.com/plugins/malware.jar', 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'Unknown', false, false)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS security_audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    username VARCHAR(50),
    source_ip VARCHAR(45),
    user_agent VARCHAR(500),
    resource VARCHAR(255),
    action VARCHAR(100),
    outcome VARCHAR(20),
    details JSONB,
    correlation_id VARCHAR(36),
    session_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '7 days')
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45),
    user_agent VARCHAR(500),
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),
    geo_location VARCHAR(100),
    session_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '7 days')
);

CREATE TABLE IF NOT EXISTS transaction_audit_trail (
    id SERIAL PRIMARY KEY,
    transaction_id VARCHAR(36) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    transaction_type VARCHAR(50) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(10) DEFAULT 'TWD',
    source_account VARCHAR(100),
    destination_account VARCHAR(100),
    status VARCHAR(20) NOT NULL,
    previous_hash VARCHAR(64),
    current_hash VARCHAR(64),
    details JSONB,
    correlation_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '90 days')
);

CREATE TABLE IF NOT EXISTS admin_action_logs (
    id SERIAL PRIMARY KEY,
    admin_user_id INTEGER REFERENCES users(id),
    admin_username VARCHAR(50),
    action_type VARCHAR(50) NOT NULL,
    target_entity VARCHAR(50),
    target_id VARCHAR(50),
    before_state JSONB,
    after_state JSONB,
    reason VARCHAR(255),
    source_ip VARCHAR(45),
    correlation_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '365 days')
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id SERIAL PRIMARY KEY,
    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    affected_user_id INTEGER REFERENCES users(id),
    affected_username VARCHAR(50),
    source_ip VARCHAR(45),
    related_log_ids INTEGER[],
    correlation_id VARCHAR(36),
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by INTEGER REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    resolved BOOLEAN DEFAULT false,
    resolved_by INTEGER REFERENCES users(id),
    resolved_at TIMESTAMP,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '90 days')
);

CREATE INDEX IF NOT EXISTS idx_security_audit_logs_correlation_id ON security_audit_logs(correlation_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_logs_created_at ON security_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_security_audit_logs_user_id ON security_audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_logs_event_type ON security_audit_logs(event_type);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_source_ip ON login_attempts(source_ip);
CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at);

CREATE INDEX IF NOT EXISTS idx_transaction_audit_trail_user_id ON transaction_audit_trail(user_id);
CREATE INDEX IF NOT EXISTS idx_transaction_audit_trail_correlation_id ON transaction_audit_trail(correlation_id);

CREATE INDEX IF NOT EXISTS idx_admin_action_logs_admin_user_id ON admin_action_logs(admin_user_id);
CREATE INDEX IF NOT EXISTS idx_admin_action_logs_created_at ON admin_action_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_acknowledged ON security_alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_security_alerts_created_at ON security_alerts(created_at);

INSERT INTO security_audit_logs (event_type, severity, user_id, username, source_ip, user_agent, resource, action, outcome, correlation_id)
VALUES 
    ('LOGIN', 'INFO', 1, 'admin', '192.168.1.100', 'Mozilla/5.0', '/api/auth/login', 'authenticate', 'SUCCESS', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'),
    ('ACCESS', 'INFO', 2, 'user', '192.168.1.101', 'Mozilla/5.0', '/api/orders/1', 'read', 'SUCCESS', 'b2c3d4e5-f6a7-8901-bcde-f12345678901'),
    ('MODIFY', 'WARN', 1, 'admin', '10.0.0.1', 'curl/7.68.0', '/api/users/3', 'update_role', 'SUCCESS', 'c3d4e5f6-a7b8-9012-cdef-123456789012'),
    ('ACCESS', 'ERROR', NULL, 'unknown', '10.0.0.99', 'sqlmap/1.5', '/api/search', 'sql_injection_attempt', 'BLOCKED', 'd4e5f6a7-b8c9-0123-def0-1234567890ab')
ON CONFLICT DO NOTHING;

INSERT INTO login_attempts (username, source_ip, user_agent, success, failure_reason)
VALUES 
    ('admin', '192.168.1.100', 'Mozilla/5.0', true, NULL),
    ('admin', '10.0.0.50', 'Python-requests/2.28.0', false, 'INVALID_PASSWORD'),
    ('admin', '10.0.0.50', 'Python-requests/2.28.0', false, 'INVALID_PASSWORD'),
    ('admin', '10.0.0.50', 'Python-requests/2.28.0', false, 'INVALID_PASSWORD'),
    ('admin', '10.0.0.50', 'Python-requests/2.28.0', false, 'INVALID_PASSWORD'),
    ('nonexistent', '10.0.0.50', 'Python-requests/2.28.0', false, 'USER_NOT_FOUND'),
    ('user', '192.168.1.101', 'Mozilla/5.0', true, NULL),
    ('locked', '192.168.1.102', 'Mozilla/5.0', false, 'ACCOUNT_LOCKED')
ON CONFLICT DO NOTHING;

INSERT INTO security_alerts (alert_type, severity, title, description, source_ip, acknowledged, resolved)
VALUES 
    ('BRUTE_FORCE', 'MEDIUM', 'Brute force attempt detected', 'IP 10.0.0.50 attempted to login to admin account 4 times in 5 minutes', '10.0.0.50', false, false),
    ('SQL_INJECTION', 'HIGH', 'SQL injection attack detected', 'Suspicious SQL syntax detected in login request', '10.0.0.51', true, true),
    ('UNAUTHORIZED_ACCESS', 'HIGH', 'Unauthorized admin access attempt', 'User tried to access admin endpoints without proper role', '192.168.1.105', false, false),
    ('SSRF', 'CRITICAL', 'SSRF attack detected', 'Attempt to access internal network resources', '10.0.0.60', false, false)
ON CONFLICT DO NOTHING;
