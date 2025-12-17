package com.owasp.vulnerable.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

/**
 * Webhook API
 */
@RestController
@RequestMapping("/api/webhook")
@RequiredArgsConstructor
public class WebhookController {

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * 測試 Webhook URL
     * 
     */
    @PostMapping("/test")
    public ResponseEntity<?> testWebhook(@RequestParam String url) {
        try {
            
            String response = restTemplate.getForObject(url, String.class);
            
            return ResponseEntity.ok(Map.of(
                "message", "Webhook 測試成功",
                "url", url,
                "response", response
            ));
        } catch (Exception e) {
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Webhook 測試失敗",
                "url", url,
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 抓取 URL 內容
     * 
     */
    @GetMapping("/fetch")
    public ResponseEntity<?> fetchUrl(@RequestParam String url) {
        try {
            
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int responseCode = connection.getResponseCode();
            
            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\n");
                }
            }

            return ResponseEntity.ok(Map.of(
                "url", url,
                "statusCode", responseCode,
                "content", content.toString(),
                "contentLength", content.length()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "抓取失敗",
                "url", url,
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 匯入資料
     * 
     */
    @PostMapping("/import")
    public ResponseEntity<?> importFromUrl(@RequestParam String url) {
        try {
            
            String data = restTemplate.getForObject(url, String.class);
            
            // 模擬處理匯入的資料
            return ResponseEntity.ok(Map.of(
                "message", "資料匯入成功",
                "source", url,
                "dataLength", data != null ? data.length() : 0,
                "preview", data != null && data.length() > 200 ? data.substring(0, 200) + "..." : data
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "匯入失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 檢查 URL 是否可用
     * 
     */
    @GetMapping("/check")
    public ResponseEntity<?> checkUrl(@RequestParam String url) {
        try {
            URL targetUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);

            int responseCode = connection.getResponseCode();

            
            return ResponseEntity.ok(Map.of(
                "url", url,
                "reachable", true,
                "statusCode", responseCode,
                "server", connection.getHeaderField("Server"),
                "contentType", connection.getContentType()
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of(
                "url", url,
                "reachable", false,
                "error", e.getMessage()
            ));
        }
    }
}
