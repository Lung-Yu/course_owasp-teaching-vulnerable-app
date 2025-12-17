package com.owasp.vulnerable.controller;

import com.owasp.common.model.Product;
import com.owasp.common.model.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 進階搜尋 API
 */
@RestController
@RequestMapping("/api/search")
@RequiredArgsConstructor
@Slf4j
public class SearchController {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 進階商品搜尋
     * 
     * 
     */
    @GetMapping("/products")
    public ResponseEntity<?> searchProducts(
            @RequestParam String keyword,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) Double minPrice,
            @RequestParam(required = false) Double maxPrice,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "asc") String order) {
        
        log.info("Product search - keyword: {}, category: {}, sortBy: {}", keyword, category, sortBy);
        
        try {
            
            StringBuilder sql = new StringBuilder(
                "SELECT * FROM products WHERE (name LIKE '%" + keyword + "%' OR description LIKE '%" + keyword + "%')");
            
            if (category != null && !category.isEmpty()) {
                
                sql.append(" AND category = '").append(category).append("'");
            }
            
            if (minPrice != null) {
                sql.append(" AND price >= ").append(minPrice);
            }
            
            if (maxPrice != null) {
                sql.append(" AND price <= ").append(maxPrice);
            }
            
            
            sql.append(" ORDER BY ").append(sortBy).append(" ").append(order);
            
            log.info("Executing SQL: {}", sql);
            
            @SuppressWarnings("unchecked")
            List<Object[]> results = entityManager.createNativeQuery(sql.toString()).getResultList();
            
            return ResponseEntity.ok(Map.of(
                "query", sql.toString(),  
                "count", results.size(),
                "results", results
            ));
        } catch (Exception e) {
            
            log.error("Search error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "搜尋失敗",
                "detail", e.getMessage(),
                "cause", e.getCause() != null ? e.getCause().getMessage() : "unknown"
            ));
        }
    }

    /**
     * 用戶搜尋
     * 
     */
    @GetMapping("/users")
    public ResponseEntity<?> searchUsers(
            @RequestParam String query,
            @RequestParam(defaultValue = "username") String field) {
        
        log.info("User search - query: {}, field: {}", query, field);
        
        try {
            
            String hql = "FROM User u WHERE u." + field + " LIKE '%" + query + "%'";
            log.info("Executing HQL: {}", hql);
            
            @SuppressWarnings("unchecked")
            List<User> users = entityManager.createQuery(hql).getResultList();
            
            List<Map<String, Object>> result = users.stream().map(u -> {
                Map<String, Object> map = new HashMap<>();
                map.put("id", u.getId());
                map.put("username", u.getUsername());
                map.put("email", u.getEmail());
                map.put("fullName", u.getFullName());
                map.put("role", u.getRole());
                
                map.put("password", u.getPassword());
                return map;
            }).toList();
            
            return ResponseEntity.ok(Map.of(
                "query", hql,
                "count", result.size(),
                "users", result
            ));
        } catch (Exception e) {
            log.error("User search error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "搜尋失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 訂單搜尋
     * 
     */
    @GetMapping("/orders")
    public ResponseEntity<?> searchOrders(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String dateFrom,
            @RequestParam(required = false) String dateTo) {
        
        log.info("Order search - status: {}, userId: {}", status, userId);
        
        try {
            StringBuilder sql = new StringBuilder("SELECT * FROM orders WHERE 1=1");
            
            if (status != null) {
                
                sql.append(" AND status = '").append(status).append("'");
            }
            
            if (userId != null) {
                
                sql.append(" AND user_id = ").append(userId);
            }
            
            if (dateFrom != null) {
                
                sql.append(" AND created_at >= '").append(dateFrom).append("'");
            }
            
            if (dateTo != null) {
                sql.append(" AND created_at <= '").append(dateTo).append("'");
            }
            
            sql.append(" ORDER BY created_at DESC");
            
            log.info("Executing SQL: {}", sql);
            
            @SuppressWarnings("unchecked")
            List<Object[]> results = entityManager.createNativeQuery(sql.toString()).getResultList();
            
            return ResponseEntity.ok(Map.of(
                "query", sql.toString(),
                "count", results.size(),
                "orders", results
            ));
        } catch (Exception e) {
            log.error("Order search error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "搜尋失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 動態報表
     * 
     * 
     */
    @PostMapping("/report")
    public ResponseEntity<?> generateReport(@RequestBody Map<String, String> request) {
        String sql = request.get("sql");
        String reportName = request.getOrDefault("name", "Custom Report");
        
        log.warn("DANGEROUS: Executing user-provided SQL: {}", sql);
        
        if (sql == null || sql.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "請提供 SQL 查詢"
            ));
        }
        
        try {
            
            @SuppressWarnings("unchecked")
            List<Object[]> results = entityManager.createNativeQuery(sql).getResultList();
            
            return ResponseEntity.ok(Map.of(
                "reportName", reportName,
                "sql", sql,
                "rowCount", results.size(),
                "data", results
            ));
        } catch (Exception e) {
            log.error("Report generation error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "報表生成失敗",
                "detail", e.getMessage(),
                "sql", sql
            ));
        }
    }

    /**
     * 資料庫表格資訊
     */
    @GetMapping("/tables")
    public ResponseEntity<?> getTables(@RequestParam(defaultValue = "public") String schema) {
        log.info("Table info request for schema: {}", schema);
        
        try {
            
            String sql = "SELECT table_name, column_name, data_type FROM information_schema.columns " +
                        "WHERE table_schema = '" + schema + "' ORDER BY table_name, ordinal_position";
            
            @SuppressWarnings("unchecked")
            List<Object[]> results = entityManager.createNativeQuery(sql).getResultList();
            
            return ResponseEntity.ok(Map.of(
                "schema", schema,
                "query", sql,
                "columns", results
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "查詢失敗",
                "detail", e.getMessage()
            ));
        }
    }
}
