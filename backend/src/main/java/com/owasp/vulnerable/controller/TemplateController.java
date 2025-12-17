package com.owasp.vulnerable.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 模板處理 API
 */
@RestController
@RequestMapping("/api/template")
@Slf4j
public class TemplateController {

    private final ExpressionParser parser = new SpelExpressionParser();

    /**
     * 計算表達式
     * 
     * 正常使用：
     * 
     * 
     */
    @GetMapping("/eval")
    public ResponseEntity<?> evaluate(@RequestParam String expression) {
        log.info("Evaluating expression: {}", expression);
        
        try {
            
            Expression exp = parser.parseExpression(expression);
            Object result = exp.getValue();
            
            return ResponseEntity.ok(Map.of(
                "expression", expression,
                "result", result != null ? result.toString() : "null",
                "type", result != null ? result.getClass().getName() : "null"
            ));
        } catch (Exception e) {
            log.error("Expression evaluation error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "表達式執行失敗",
                "expression", expression,
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 模板渲染
     * 
     * 正常使用：
     * 
     */
    @PostMapping("/render")
    public ResponseEntity<?> render(@RequestBody Map<String, Object> request) {
        String template = (String) request.get("template");
        @SuppressWarnings("unchecked")
        Map<String, Object> variables = (Map<String, Object>) request.getOrDefault("variables", new HashMap<>());
        
        log.info("Rendering template: {} with variables: {}", template, variables);
        
        if (template == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "請提供 template 參數"
            ));
        }
        
        try {
            // 建立上下文並設置變數
            StandardEvaluationContext context = new StandardEvaluationContext();
            variables.forEach((key, value) -> context.setVariable(key, value));
            
            
            String result = template;
            
            // 尋找並替換 #{...} 表達式
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("#\\{([^}]+)\\}");
            java.util.regex.Matcher matcher = pattern.matcher(template);
            StringBuffer sb = new StringBuffer();
            
            while (matcher.find()) {
                String expr = matcher.group(1);
                try {
                    Expression exp = parser.parseExpression(expr);
                    Object value = exp.getValue(context);
                    matcher.appendReplacement(sb, value != null ? value.toString() : "null");
                } catch (Exception e) {
                    matcher.appendReplacement(sb, "[ERROR: " + e.getMessage() + "]");
                }
            }
            matcher.appendTail(sb);
            result = sb.toString();
            
            return ResponseEntity.ok(Map.of(
                "template", template,
                "variables", variables,
                "rendered", result
            ));
        } catch (Exception e) {
            log.error("Template rendering error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "模板渲染失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 格式化訊息
     * 
     */
    @PostMapping("/format")
    public ResponseEntity<?> format(@RequestBody Map<String, Object> request) {
        String format = (String) request.get("format");
        @SuppressWarnings("unchecked")
        java.util.List<String> args = (java.util.List<String>) request.getOrDefault("args", java.util.List.of());
        
        log.info("Formatting: {} with args: {}", format, args);
        
        if (format == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "請提供 format 參數"
            ));
        }
        
        try {
            
            Object[] processedArgs = args.stream().map(arg -> {
                if (arg.contains("#{") || arg.startsWith("T(") || arg.startsWith("new ")) {
                    try {
                        // 處理 #{...} 包裝
                        String expr = arg;
                        if (expr.startsWith("#{") && expr.endsWith("}")) {
                            expr = expr.substring(2, expr.length() - 1);
                        }
                        Expression exp = parser.parseExpression(expr);
                        return exp.getValue();
                    } catch (Exception e) {
                        return "[ERROR: " + e.getMessage() + "]";
                    }
                }
                return arg;
            }).toArray();
            
            String result = String.format(format, processedArgs);
            
            return ResponseEntity.ok(Map.of(
                "format", format,
                "args", args,
                "result", result
            ));
        } catch (Exception e) {
            log.error("Format error", e);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "格式化失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 動態屬性存取
     */
    @GetMapping("/property")
    public ResponseEntity<?> getProperty(@RequestParam String path) {
        log.info("Accessing property path: {}", path);
        
        try {
            
            Expression exp = parser.parseExpression(path);
            Object result = exp.getValue();
            
            return ResponseEntity.ok(Map.of(
                "path", path,
                "value", result != null ? result.toString() : "null"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "屬性存取失敗",
                "path", path,
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 條件檢查
     */
    @PostMapping("/check")
    public ResponseEntity<?> check(@RequestBody Map<String, String> request) {
        String condition = request.get("condition");
        String trueValue = request.getOrDefault("trueValue", "true");
        String falseValue = request.getOrDefault("falseValue", "false");
        
        log.info("Checking condition: {}", condition);
        
        if (condition == null) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "請提供 condition 參數"
            ));
        }
        
        try {
            
            Expression exp = parser.parseExpression(condition);
            Boolean result = exp.getValue(Boolean.class);
            
            return ResponseEntity.ok(Map.of(
                "condition", condition,
                "result", result != null && result ? trueValue : falseValue,
                "boolValue", result
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "條件檢查失敗",
                "condition", condition,
                "detail", e.getMessage()
            ));
        }
    }
}
