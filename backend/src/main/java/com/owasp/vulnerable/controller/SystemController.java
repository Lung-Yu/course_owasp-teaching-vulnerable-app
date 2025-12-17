package com.owasp.vulnerable.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 系統工具 API
 */
@RestController
@RequestMapping("/api/system")
@Slf4j
public class SystemController {

    /**
     * Ping 主機
     * 
     */
    @GetMapping("/ping")
    public ResponseEntity<?> ping(@RequestParam String host) {
        log.info("Ping request for host: {}", host);
        
        try {
            
            String command = "ping -c 3 " + host;
            log.info("Executing command: {}", command);
            
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines()
                    .collect(Collectors.joining("\n"));
            
            int exitCode = process.waitFor();
            
            return ResponseEntity.ok(Map.of(
                "command", command,  
                "output", output,
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "執行失敗",
                "detail", e.getMessage(),
                "type", e.getClass().getName()
            ));
        }
    }

    /**
     * DNS 查詢
     * 
     */
    @GetMapping("/lookup")
    public ResponseEntity<?> lookup(@RequestParam String domain) {
        log.info("Lookup request for domain: {}", domain);
        
        try {
            
            String command = "nslookup " + domain;
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines()
                    .collect(Collectors.joining("\n"));
            
            int exitCode = process.waitFor();
            
            return ResponseEntity.ok(Map.of(
                "command", command,
                "output", output,
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "查詢失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 系統資訊
     * 
     */
    @GetMapping("/info")
    public ResponseEntity<?> systemInfo(@RequestParam(defaultValue = "uname -a") String cmd) {
        log.info("System info request with cmd: {}", cmd);
        
        try {
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines()
                    .collect(Collectors.joining("\n"));
            
            int exitCode = process.waitFor();
            
            return ResponseEntity.ok(Map.of(
                "command", cmd,
                "output", output,
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "執行失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 檔案讀取工具
     * 
     */
    @GetMapping("/read-log")
    public ResponseEntity<?> readLog(@RequestParam String filename) {
        log.info("Read log request for: {}", filename);
        
        try {
            
            String command = "cat /var/log/" + filename;
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines()
                    .collect(Collectors.joining("\n"));
            
            int exitCode = process.waitFor();
            
            return ResponseEntity.ok(Map.of(
                "command", command,
                "output", output,
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "讀取失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 網路診斷
     * 
     */
    @PostMapping("/diagnose")
    public ResponseEntity<?> diagnose(@RequestBody Map<String, String> request) {
        String target = request.getOrDefault("target", "localhost");
        String ports = request.getOrDefault("ports", "80");
        String tool = request.getOrDefault("tool", "nc");
        
        log.info("Diagnose request - target: {}, ports: {}, tool: {}", target, ports, tool);
        
        try {
            
            String command;
            switch (tool) {
                case "curl":
                    command = "curl -s -o /dev/null -w '%{http_code}' " + target;
                    break;
                case "wget":
                    command = "wget -q --spider " + target + " && echo 'OK' || echo 'FAIL'";
                    break;
                case "nc":
                default:
                    command = "nc -zv " + target + " " + ports + " 2>&1";
                    break;
            }
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                    .lines()
                    .collect(Collectors.joining("\n"));
            
            int exitCode = process.waitFor();
            
            return ResponseEntity.ok(Map.of(
                "command", command,
                "output", output,
                "exitCode", exitCode,
                "tool", tool
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "診斷失敗",
                "detail", e.getMessage()
            ));
        }
    }
}
