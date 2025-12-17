package com.owasp.vulnerable.service;

import com.owasp.common.model.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * JWT 服務
 */
@Service
public class VulnerableJwtService {

    
    private static final String WEAK_SECRET = "secret";
    
    // 為了能「生成」token，還是需要一個 key
    private static final String SIGNING_KEY = "vulnerable-jwt-secret-key-12345678901234567890";

    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper = 
            new com.fasterxml.jackson.databind.ObjectMapper();

    /**
     * 生成 JWT Token
     */
    public String generateToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", user.getId());
        claims.put("username", user.getUsername());
        claims.put("role", user.getRole().name());
        claims.put("email", user.getEmail());

        SecretKey key = Keys.hmacShaKeyFor(SIGNING_KEY.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .claims(claims)
                .subject(user.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 86400000)) // 24 hours
                .signWith(key)
                .compact();
    }

    /**
     * 解析 JWT Token
     * 
     * 這個方法只 decode token，完全不驗證簽名
     * 2. 將 header 中的 alg 改為 "none"
     * 
     * @return Map containing the claims (not the actual Claims interface)
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> parseTokenWithoutVerification(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return null;
            }

            // Base64 decode payload
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            
            // 使用 Jackson 解析 JSON 到 Map
            return objectMapper.readValue(payload, Map.class);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 從 claims Map 取得使用者 ID
     */
    public Long getUserIdFromClaims(Map<String, Object> claims) {
        if (claims == null) return null;
        Object userId = claims.get("userId");
        if (userId instanceof Integer) {
            return ((Integer) userId).longValue();
        } else if (userId instanceof Long) {
            return (Long) userId;
        }
        return null;
    }

    /**
     * 從 claims Map 取得使用者名稱
     */
    public String getUsernameFromClaims(Map<String, Object> claims) {
        if (claims == null) return null;
        return (String) claims.get("username");
    }

    /**
     * 從 claims Map 取得角色
     */
    public String getRoleFromClaims(Map<String, Object> claims) {
        if (claims == null) return null;
        return (String) claims.get("role");
    }

    /**
     * 驗證 token 是否有效
     */
    public boolean validateToken(String token) {
        
        Map<String, Object> claims = parseTokenWithoutVerification(token);
        return claims != null;
    }
}
