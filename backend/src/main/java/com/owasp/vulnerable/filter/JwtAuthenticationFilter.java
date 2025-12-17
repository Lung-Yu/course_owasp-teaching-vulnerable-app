package com.owasp.vulnerable.filter;

import com.owasp.vulnerable.service.VulnerableJwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

/**
 * JWT 認證過濾器
 * 
 * 1. 不驗證 JWT 簽名
 * 2. 接受任意修改的 token
 * 3. 不檢查過期時間
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final VulnerableJwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                    HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            
            Map<String, Object> claims = jwtService.parseTokenWithoutVerification(token);
            
            if (claims != null) {
                Long userId = jwtService.getUserIdFromClaims(claims);
                String username = jwtService.getUsernameFromClaims(claims);
                String role = jwtService.getRoleFromClaims(claims);
                
                if (username != null && role != null) {
                    
                    SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + role);
                    
                    // 建立自訂的 Principal，包含 userId
                    JwtUserPrincipal principal = new JwtUserPrincipal(userId, username, role);
                    
                    UsernamePasswordAuthenticationToken authentication = 
                        new UsernamePasswordAuthenticationToken(principal, null, Collections.singletonList(authority));
                    
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }

    /**
     * 自訂的 Principal，包含使用者資訊
     */
    public static class JwtUserPrincipal {
        private final Long id;
        private final String username;
        private final String role;

        public JwtUserPrincipal(Long id, String username, String role) {
            this.id = id;
            this.username = username;
            this.role = role;
        }

        public Long getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }

        public String getRole() {
            return role;
        }

        @Override
        public String toString() {
            return username;
        }
    }
}
