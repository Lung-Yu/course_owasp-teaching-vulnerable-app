package com.owasp.vulnerable.controller;

import com.owasp.common.dto.ProductDTO;
import com.owasp.common.model.Product;
import com.owasp.common.repository.ProductRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 商品 API
 */
@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductRepository productRepository;

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 取得所有商品
     */
    @GetMapping
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(productRepository.findByActiveTrue());
    }

    /**
     * 取得單一商品
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getProduct(@PathVariable Long id) {
        return productRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 搜尋商品
     * 
     */
    @GetMapping("/search")
    public ResponseEntity<?> searchProducts(@RequestParam String keyword) {
        
        String sql = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%' OR description LIKE '%" + keyword + "%'";
        
        try {
            @SuppressWarnings("unchecked")
            List<Product> products = entityManager.createNativeQuery(sql, Product.class).getResultList();
            return ResponseEntity.ok(products);
        } catch (Exception e) {
            
            return ResponseEntity.badRequest().body(Map.of(
                "error", "搜尋失敗",
                "detail", e.getMessage(),
                "sql", sql
            ));
        }
    }

    /**
     * 新增商品
     */
    @PostMapping
    public ResponseEntity<?> createProduct(@RequestBody ProductDTO dto) {
        
        
        Product product = Product.builder()
                .name(dto.getName())          // 未過濾
                .description(dto.getDescription())  // 未過濾
                .price(dto.getPrice())
                .stock(dto.getStock())
                .category(dto.getCategory())
                .imageUrl(dto.getImageUrl())
                .active(true)
                .build();

        productRepository.save(product);

        return ResponseEntity.ok(Map.of(
            "message", "商品新增成功",
            "id", product.getId()
        ));
    }

    /**
     * 更新商品
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateProduct(@PathVariable Long id, @RequestBody ProductDTO dto) {
        return productRepository.findById(id)
                .map(product -> {
                    
                    product.setName(dto.getName());
                    product.setDescription(dto.getDescription());
                    product.setPrice(dto.getPrice());
                    product.setStock(dto.getStock());
                    product.setCategory(dto.getCategory());
                    product.setImageUrl(dto.getImageUrl());
                    productRepository.save(product);
                    return ResponseEntity.ok(Map.of("message", "商品更新成功"));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 刪除商品
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteProduct(@PathVariable Long id) {
        
        if (productRepository.existsById(id)) {
            productRepository.deleteById(id);
            return ResponseEntity.ok(Map.of("message", "商品刪除成功"));
        }
        return ResponseEntity.notFound().build();
    }
}
