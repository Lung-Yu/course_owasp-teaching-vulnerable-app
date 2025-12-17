package com.owasp.vulnerable.controller;

import com.owasp.common.dto.OrderDTO;
import com.owasp.common.dto.OrderItemDTO;
import com.owasp.common.model.Order;
import com.owasp.common.model.OrderItem;
import com.owasp.common.model.Product;
import com.owasp.common.model.User;
import com.owasp.common.repository.OrderRepository;
import com.owasp.common.repository.ProductRepository;
import com.owasp.common.repository.UserRepository;
import com.owasp.vulnerable.filter.JwtAuthenticationFilter.JwtUserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * 訂單 API
 */
@RestController
@RequestMapping("/api/orders")
@RequiredArgsConstructor
public class OrderController {

    private final OrderRepository orderRepository;
    private final UserRepository userRepository;
    private final ProductRepository productRepository;

    /**
     * 取得所有訂單
     */
    @GetMapping
    public ResponseEntity<List<OrderDTO>> getAllOrders() {
        
        List<OrderDTO> orders = orderRepository.findAll().stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(orders);
    }

    /**
     * 取得訂單詳情
     * 
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getOrder(@PathVariable Long id) {
        
        return orderRepository.findById(id)
                .map(order -> ResponseEntity.ok(toDTO(order)))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 透過訂單號查詢
     * 
     */
    @GetMapping("/number/{orderNumber}")
    public ResponseEntity<?> getOrderByNumber(@PathVariable String orderNumber) {
        
        return orderRepository.findByOrderNumber(orderNumber)
                .map(order -> ResponseEntity.ok(toDTO(order)))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 建立訂單
     */
    @PostMapping
    public ResponseEntity<?> createOrder(@RequestBody CreateOrderRequest request, 
                                         Authentication authentication) {
        JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
        
        User user = userRepository.findById(principal.getId())
                .orElseThrow(() -> new RuntimeException("使用者不存在"));

        
        String orderNumber = String.format("ORD-%05d", orderRepository.count() + 1);

        Order order = Order.builder()
                .orderNumber(orderNumber)
                .user(user)
                .shippingAddress(request.getShippingAddress())
                .note(request.getNote())
                .status(Order.Status.PENDING)
                .totalAmount(BigDecimal.ZERO)
                .build();

        BigDecimal total = BigDecimal.ZERO;
        for (CreateOrderRequest.Item item : request.getItems()) {
            Product product = productRepository.findById(item.getProductId())
                    .orElseThrow(() -> new RuntimeException("商品不存在"));

            OrderItem orderItem = OrderItem.builder()
                    .order(order)
                    .product(product)
                    .quantity(item.getQuantity())
                    .unitPrice(product.getPrice())
                    .subtotal(product.getPrice().multiply(BigDecimal.valueOf(item.getQuantity())))
                    .build();

            order.getItems().add(orderItem);
            total = total.add(orderItem.getSubtotal());
        }

        order.setTotalAmount(total);
        orderRepository.save(order);

        return ResponseEntity.ok(Map.of(
            "message", "訂單建立成功",
            "orderNumber", orderNumber,
            "orderId", order.getId()
        ));
    }

    /**
     * 更新訂單
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateOrder(@PathVariable Long id, 
                                         @RequestBody UpdateOrderRequest request) {
        
        return orderRepository.findById(id)
                .map(order -> {
                    if (request.getShippingAddress() != null) {
                        order.setShippingAddress(request.getShippingAddress());
                    }
                    if (request.getNote() != null) {
                        order.setNote(request.getNote());
                    }
                    if (request.getStatus() != null) {
                        
                        order.setStatus(Order.Status.valueOf(request.getStatus()));
                    }
                    orderRepository.save(order);
                    return ResponseEntity.ok(Map.of("message", "訂單更新成功"));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 刪除訂單
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteOrder(@PathVariable Long id) {
        
        if (orderRepository.existsById(id)) {
            orderRepository.deleteById(id);
            return ResponseEntity.ok(Map.of("message", "訂單刪除成功"));
        }
        return ResponseEntity.notFound().build();
    }

    private OrderDTO toDTO(Order order) {
        List<OrderItemDTO> items = order.getItems().stream()
                .map(item -> OrderItemDTO.builder()
                        .id(item.getId())
                        .productId(item.getProduct().getId())
                        .productName(item.getProduct().getName())
                        .quantity(item.getQuantity())
                        .unitPrice(item.getUnitPrice())
                        .subtotal(item.getSubtotal())
                        .build())
                .collect(Collectors.toList());

        return OrderDTO.builder()
                .id(order.getId())
                .orderNumber(order.getOrderNumber())
                .userId(order.getUser().getId())
                .username(order.getUser().getUsername())
                .items(items)
                .totalAmount(order.getTotalAmount())
                .status(order.getStatus().name())
                .shippingAddress(order.getShippingAddress())
                .note(order.getNote())
                .createdAt(order.getCreatedAt())
                .build();
    }

    @lombok.Data
    public static class CreateOrderRequest {
        private List<Item> items;
        private String shippingAddress;
        private String note;

        @lombok.Data
        public static class Item {
            private Long productId;
            private Integer quantity;
        }
    }

    @lombok.Data
    public static class UpdateOrderRequest {
        private String shippingAddress;
        private String note;
        private String status;
    }

    // ========================================
    // ========================================

    /**
     * 結帳端點
     * 
     */
    @PostMapping("/checkout")
    public ResponseEntity<?> checkout(@RequestBody CheckoutRequest request, 
                                       Authentication authentication) {
        // 獲取用戶（允許匿名測試）
        User user;
        if (authentication != null && authentication.getPrincipal() instanceof JwtUserPrincipal) {
            JwtUserPrincipal principal = (JwtUserPrincipal) authentication.getPrincipal();
            user = userRepository.findById(principal.getId())
                    .orElseThrow(() -> new RuntimeException("使用者不存在"));
        } else {
            // 匿名用戶使用測試帳戶
            user = userRepository.findByUsername("user")
                    .orElseGet(() -> userRepository.findById(1L)
                            .orElseThrow(() -> new RuntimeException("無法找到測試用戶")));
        }

        BigDecimal clientTotal = request.getTotalAmount();
                
        String orderNumber = "ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        Order order = Order.builder()
                .orderNumber(orderNumber)
                .user(user)
                .shippingAddress(request.getShippingAddress())
                .note(request.getNote())
                .status(Order.Status.PENDING)
                .totalAmount(clientTotal)  
                .build();

        BigDecimal serverCalculatedTotal = BigDecimal.ZERO;
        
        for (CheckoutRequest.Item item : request.getItems()) {
            Product product = productRepository.findById(item.getProductId())
                    .orElseThrow(() -> new RuntimeException("商品不存在"));

            
            BigDecimal itemPrice = item.getUnitPrice() != null 
                ? item.getUnitPrice()  
                : product.getPrice();

            
            
            BigDecimal subtotal = itemPrice.multiply(BigDecimal.valueOf(item.getQuantity()));

            OrderItem orderItem = OrderItem.builder()
                    .order(order)
                    .product(product)
                    .quantity(item.getQuantity())
                    .unitPrice(itemPrice)
                    .subtotal(subtotal)
                    .build();

            order.getItems().add(orderItem);
            serverCalculatedTotal = serverCalculatedTotal.add(subtotal);
        }

        BigDecimal priceDifference = serverCalculatedTotal.subtract(clientTotal);

        orderRepository.save(order);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "結帳成功");
        response.put("orderNumber", orderNumber);
        response.put("orderId", order.getId());
        response.put("chargedAmount", clientTotal);
        response.put("actualValue", serverCalculatedTotal);
        response.put("savings", priceDifference);
        response.put("status", "PENDING");
        
        if (priceDifference.compareTo(BigDecimal.ZERO) != 0) {
            response.put("warning", "價格不一致！客戶端價格: " + clientTotal + ", 實際價值: " + serverCalculatedTotal);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * 更新訂單狀態
     * 
     */
    @PutMapping("/{id}/status")
    public ResponseEntity<?> updateOrderStatus(@PathVariable Long id, 
                                                @RequestBody Map<String, String> request) {
        String newStatus = request.get("status");
        
        return orderRepository.findById(id)
                .map(order -> {
                    String oldStatus = order.getStatus().name();
                    
                    try {
                        Order.Status status = Order.Status.valueOf(newStatus);
                        order.setStatus(status);
                        orderRepository.save(order);
                        
                        return ResponseEntity.ok(Map.of(
                            "message", "狀態更新成功",
                            "orderId", id,
                            "oldStatus", oldStatus,
                            "newStatus", newStatus,
                            "warning", "狀態從 " + oldStatus + " 直接跳轉到 " + newStatus + " - 未驗證工作流程！"
                        ));
                    } catch (IllegalArgumentException e) {
                        return ResponseEntity.badRequest().body(Map.of(
                            "error", "無效的狀態",
                            "validStatuses", Order.Status.values()
                        ));
                    }
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * 申請退款
     */
    @PostMapping("/{id}/refund")
    public ResponseEntity<?> requestRefund(@PathVariable Long id, 
                                            @RequestBody Map<String, Object> request) {
        BigDecimal refundAmount = new BigDecimal(request.getOrDefault("amount", "0").toString());
        String reason = (String) request.getOrDefault("reason", "無原因");
        
        return orderRepository.findById(id)
                .map(order -> {
                    
                    BigDecimal orderTotal = order.getTotalAmount();
                    
                    // 模擬處理退款
                    return ResponseEntity.ok(Map.of(
                        "message", "退款申請已提交",
                        "orderId", id,
                        "orderStatus", order.getStatus().name(),
                        "orderTotal", orderTotal,
                        "refundAmount", refundAmount,
                        "reason", reason,
                        "warning", refundAmount.compareTo(orderTotal) > 0 
                            ? "退款金額超過訂單總額！" : null,
                        "statusWarning", order.getStatus() != Order.Status.DELIVERED 
                            ? "訂單尚未送達就申請退款！" : null
                    ));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @lombok.Data
    public static class CheckoutRequest {
        private List<Item> items;
        private String shippingAddress;
        private String note;
        private BigDecimal totalAmount;  
        private String couponCode;

        @lombok.Data
        public static class Item {
            private Long productId;
            private Integer quantity;
            private BigDecimal unitPrice;  
        }
    }
}
