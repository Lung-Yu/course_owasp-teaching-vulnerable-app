package com.owasp.vulnerable.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * 檔案 API
 */
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class FileController {

    // 上傳目錄
    private static final String UPLOAD_DIR = "/app/uploads";

    /**
     * 下載檔案
     * 
     */
    @GetMapping("/download")
    public ResponseEntity<?> downloadFile(@RequestParam String filename) {
        try {
            
            Path filePath = Paths.get(UPLOAD_DIR, filename);
            
            
            if (!Files.exists(filePath)) {
                return ResponseEntity.notFound().build();
            }

            Resource resource = new UrlResource(filePath.toUri());
            
            String contentType = Files.probeContentType(filePath);
            if (contentType == null) {
                contentType = "application/octet-stream";
            }

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(contentType))
                    .header(HttpHeaders.CONTENT_DISPOSITION, 
                            "attachment; filename=\"" + filePath.getFileName().toString() + "\"")
                    .body(resource);
        } catch (IOException e) {
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "檔案讀取失敗",
                "detail", e.getMessage(),
                "path", UPLOAD_DIR + "/" + filename
            ));
        }
    }

    /**
     * 讀取檔案內容
     * 
     */
    @GetMapping("/read")
    public ResponseEntity<?> readFile(@RequestParam String filename) {
        try {
            
            Path filePath = Paths.get(UPLOAD_DIR, filename);
            
            if (!Files.exists(filePath)) {
                return ResponseEntity.notFound().build();
            }

            String content = Files.readString(filePath);
            
            return ResponseEntity.ok(Map.of(
                "filename", filename,
                "content", content,
                "size", Files.size(filePath)
            ));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "檔案讀取失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 列出檔案
     * 
     */
    @GetMapping("/list")
    public ResponseEntity<?> listFiles(@RequestParam(defaultValue = "") String dir) {
        try {
            
            Path dirPath = Paths.get(UPLOAD_DIR, dir);
            
            if (!Files.exists(dirPath) || !Files.isDirectory(dirPath)) {
                return ResponseEntity.notFound().build();
            }

            var files = Files.list(dirPath)
                    .map(path -> Map.of(
                        "name", path.getFileName().toString(),
                        "isDirectory", Files.isDirectory(path),
                        "size", getFileSize(path)
                    ))
                    .toList();

            return ResponseEntity.ok(Map.of(
                "directory", dir.isEmpty() ? "/" : dir,
                "files", files
            ));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "目錄讀取失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 上傳檔案
     */
    @PostMapping("/upload")
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file,
                                        @RequestParam(defaultValue = "") String subdir) {
        try {
            
            
            Path uploadPath = Paths.get(UPLOAD_DIR, subdir);
            
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            
            String filename = file.getOriginalFilename();
            Path filePath = uploadPath.resolve(filename);
            
            Files.copy(file.getInputStream(), filePath);

            return ResponseEntity.ok(Map.of(
                "message", "檔案上傳成功",
                "filename", filename,
                "path", filePath.toString(),
                "size", file.getSize()
            ));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "檔案上傳失敗",
                "detail", e.getMessage()
            ));
        }
    }

    /**
     * 刪除檔案
     */
    @DeleteMapping("/delete")
    public ResponseEntity<?> deleteFile(@RequestParam String filename) {
        try {
            
            Path filePath = Paths.get(UPLOAD_DIR, filename);
            
            if (!Files.exists(filePath)) {
                return ResponseEntity.notFound().build();
            }

            Files.delete(filePath);
            
            return ResponseEntity.ok(Map.of(
                "message", "檔案刪除成功",
                "filename", filename
            ));
        } catch (IOException e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "檔案刪除失敗",
                "detail", e.getMessage()
            ));
        }
    }

    private long getFileSize(Path path) {
        try {
            return Files.size(path);
        } catch (IOException e) {
            return -1;
        }
    }
}
