-- =====================================================
-- OWASP Demo - 資料初始化腳本
-- =====================================================
-- 這個檔案會在 JPA 建立表格後執行

-- 初始化使用者資料
-- 注意：漏洞版本使用明文密碼展示
INSERT INTO users (username, password, email, full_name, role, enabled, created_at)
SELECT 'admin', 'admin123', 'admin@example.com', '系統管理員', 'ADMIN', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');

INSERT INTO users (username, password, email, full_name, role, enabled, created_at)
SELECT 'user', 'user123', 'user@example.com', '測試使用者', 'USER', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'user');

INSERT INTO users (username, password, email, full_name, role, enabled, created_at)
SELECT 'alice', 'alice123', 'alice@example.com', 'Alice Wang', 'USER', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'alice');

INSERT INTO users (username, password, email, full_name, role, enabled, created_at)
SELECT 'bob', 'bob123', 'bob@example.com', 'Bob Chen', 'USER', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'bob');

-- 初始化商品資料
INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT 'MacBook Pro 14吋', '搭載 M3 Pro 晶片，18GB 統一記憶體，512GB SSD。', 59900.00, 10, '電子產品', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = 'MacBook Pro 14吋');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT 'iPhone 15 Pro', '搭載 A17 Pro 晶片，鈦金屬設計，動態島功能。', 36900.00, 25, '電子產品', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = 'iPhone 15 Pro');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT 'AirPods Pro', '主動式降噪功能，通透模式，MagSafe 充電盒。', 7490.00, 30, '電子產品', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = 'AirPods Pro');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT 'iPad Air', '搭載 M1 晶片，10.9 吋 Liquid Retina 顯示器。', 19900.00, 15, '電子產品', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = 'iPad Air');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT '經典白T恤', '100% 純棉材質，舒適透氣，經典百搭。', 590.00, 100, '服飾', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = '經典白T恤');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT '牛仔褲', '經典直筒版型，彈性舒適。耐穿耐洗。', 1290.00, 50, '服飾', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = '牛仔褲');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT '連帽外套', '保暖刷毛內裡，寬鬆版型。', 1490.00, 40, '服飾', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = '連帽外套');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT '程式設計入門', '從零開始學習程式設計，適合初學者。', 480.00, 200, '書籍', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = '程式設計入門');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT '資安實戰手冊', '深入了解 OWASP Top 10 弱點與防禦方法。', 680.00, 150, '書籍', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = '資安實戰手冊');

INSERT INTO products (name, description, price, stock, category, active, created_at)
SELECT '演算法圖鑑', '用圖解方式講解常見演算法。', 520.00, 180, '書籍', true, NOW()
WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = '演算法圖鑑');
