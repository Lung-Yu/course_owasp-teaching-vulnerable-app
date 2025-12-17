package com.owasp.vulnerable.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * 加密 API
 */
@RestController
@RequestMapping("/api/crypto")
@Slf4j
public class CryptoController {

    
    private static final String DES_KEY = "12345678";  // DES 需要 8 bytes
    private static final String AES_KEY = "1234567890123456";  // AES-128 需要 16 bytes
    
    
    private final Random random = new Random(System.currentTimeMillis());
    
    private final List<String> generatedTokens = new ArrayList<>();

    /**
     * 使用 DES 加密資料
     */
    @PostMapping("/encrypt")
    public ResponseEntity<?> encrypt(@RequestBody Map<String, String> request) {
        String data = request.get("data");
        String algorithm = request.getOrDefault("algorithm", "DES");
        
        try {
            String encrypted;
            if ("AES".equalsIgnoreCase(algorithm)) {
                encrypted = encryptAES(data);
            } else {
                
                encrypted = encryptDES(data);
            }
            
            return ResponseEntity.ok(Map.of(
                "original", data,
                "encrypted", encrypted,
                "algorithm", algorithm,
                "keyUsed", algorithm.equalsIgnoreCase("AES") ? AES_KEY : DES_KEY  
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * 解密資料
     */
    @PostMapping("/decrypt")
    public ResponseEntity<?> decrypt(@RequestBody Map<String, String> request) {
        String data = request.get("data");
        String algorithm = request.getOrDefault("algorithm", "DES");
        
        try {
            String decrypted;
            if ("AES".equalsIgnoreCase(algorithm)) {
                decrypted = decryptAES(data);
            } else {
                decrypted = decryptDES(data);
            }
            
            return ResponseEntity.ok(Map.of(
                "encrypted", data,
                "decrypted", decrypted,
                "algorithm", algorithm
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * 使用 MD5 雜湊密碼
     */
    @PostMapping("/hash")
    public ResponseEntity<?> hashPassword(@RequestBody Map<String, String> request) {
        String password = request.get("password");
        String algorithm = request.getOrDefault("algorithm", "MD5");
        
        try {
            String hash;
            if ("SHA1".equalsIgnoreCase(algorithm)) {
                
                hash = hashWithAlgorithm(password, "SHA-1");
            } else {
                
                hash = hashWithAlgorithm(password, "MD5");
            }
            
            return ResponseEntity.ok(Map.of(
                "password", password,  
                "hash", hash,
                "algorithm", algorithm,
                "warning", "此雜湊可被彩虹表破解"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * 驗證雜湊
     */
    @PostMapping("/verify-hash")
    public ResponseEntity<?> verifyHash(@RequestBody Map<String, String> request) {
        String password = request.get("password");
        String hash = request.get("hash");
        String algorithm = request.getOrDefault("algorithm", "MD5");
        
        try {
            String computedHash = hashWithAlgorithm(password, 
                "SHA1".equalsIgnoreCase(algorithm) ? "SHA-1" : "MD5");
            boolean matches = computedHash.equalsIgnoreCase(hash);
            
            return ResponseEntity.ok(Map.of(
                "matches", matches,
                "computedHash", computedHash
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * 生成 Token（折扣碼、訂單編號等）
     */
    @PostMapping("/generate-token")
    public ResponseEntity<?> generateToken(@RequestBody Map<String, String> request) {
        String type = request.getOrDefault("type", "discount");
        int count = Integer.parseInt(request.getOrDefault("count", "1"));
        
        List<String> tokens = new ArrayList<>();
        
        for (int i = 0; i < Math.min(count, 10); i++) {
            String token;
            if ("order".equals(type)) {
                
                token = "ORD-" + String.format("%08d", random.nextInt(100000000));
            } else {
                
                token = "DISC-" + String.format("%06d", random.nextInt(1000000));
            }
            tokens.add(token);
            generatedTokens.add(token);
        }
        
        return ResponseEntity.ok(Map.of(
            "tokens", tokens,
            "type", type,
            "warning", "這些 token 是使用 java.util.Random 生成的，可被預測"
        ));
    }

    /**
     * 取得已生成的 Token 歷史（用於分析預測）
     */
    @GetMapping("/token-history")
    public ResponseEntity<?> getTokenHistory() {
        return ResponseEntity.ok(Map.of(
            "tokens", generatedTokens,
            "count", generatedTokens.size(),
            "hint", "分析這些 token 可以推算 Random 的 seed"
        ));
    }

    /**
     */
    @PostMapping("/reset-random")
    public ResponseEntity<?> resetRandom(@RequestBody Map<String, Object> request) {
        long seed = ((Number) request.getOrDefault("seed", System.currentTimeMillis())).longValue();
        random.setSeed(seed);
        generatedTokens.clear();
        
        return ResponseEntity.ok(Map.of(
            "message", "Random seed 已重設",
            "seed", seed,  
            "warning", "知道 seed 就可以預測所有後續 token"
        ));
    }

    // ========== 內部方法 ==========

    /**
     */
    private String encryptDES(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * DES 解密
     */
    private String decryptDES(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(DES_KEY.getBytes(StandardCharsets.UTF_8), "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     */
    private String encryptAES(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");  
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * AES 解密
     */
    private String decryptAES(String data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     */
    private String hashWithAlgorithm(String data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
