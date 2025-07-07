package com.winnguyen1905.gateway.controller;

import com.winnguyen1905.gateway.common.RegionPartition;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Fallback controller for handling circuit breaker fallbacks when services are unavailable.
 * Provides graceful degradation responses with regional context.
 */
@RestController
@RequestMapping("/fallback")
@Slf4j
public class FallbackController {

    /**
     * Fallback for Product Service
     */
    @GetMapping("/product")
    public ResponseEntity<Map<String, Object>> productServiceFallback(ServerWebExchange exchange) {
        RegionPartition region = getRegionFromExchange(exchange);
        
        log.warn("Product service fallback triggered for region: {}", region.getCode());
        
        Map<String, Object> response = createFallbackResponse(
            "Product Service Temporarily Unavailable",
            "Our product service is currently experiencing issues. Please try again in a few moments.",
            region
        );
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Fallback for Order Service
     */
    @GetMapping("/order")
    public ResponseEntity<Map<String, Object>> orderServiceFallback(ServerWebExchange exchange) {
        RegionPartition region = getRegionFromExchange(exchange);
        
        log.warn("Order service fallback triggered for region: {}", region.getCode());
        
        Map<String, Object> response = createFallbackResponse(
            "Order Service Temporarily Unavailable",
            "Our order processing service is currently experiencing issues. Your orders are safe and we'll process them as soon as possible.",
            region
        );
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Fallback for Cart Service
     */
    @GetMapping("/cart")
    public ResponseEntity<Map<String, Object>> cartServiceFallback(ServerWebExchange exchange) {
        RegionPartition region = getRegionFromExchange(exchange);
        
        log.warn("Cart service fallback triggered for region: {}", region.getCode());
        
        Map<String, Object> response = createFallbackResponse(
            "Cart Service Temporarily Unavailable",
            "Our shopping cart service is currently experiencing issues. Your cart data is safe.",
            region
        );
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Fallback for Payment Service
     */
    @GetMapping("/payment")
    public ResponseEntity<Map<String, Object>> paymentServiceFallback(ServerWebExchange exchange) {
        RegionPartition region = getRegionFromExchange(exchange);
        
        log.warn("Payment service fallback triggered for region: {}", region.getCode());
        
        Map<String, Object> response = createFallbackResponse(
            "Payment Service Temporarily Unavailable",
            "Our payment processing service is currently experiencing issues. Please try your payment again in a few moments.",
            region
        );
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Generic fallback for unknown services
     */
    @GetMapping("/generic")
    public ResponseEntity<Map<String, Object>> genericServiceFallback(ServerWebExchange exchange) {
        RegionPartition region = getRegionFromExchange(exchange);
        
        log.warn("Generic service fallback triggered for region: {}", region.getCode());
        
        Map<String, Object> response = createFallbackResponse(
            "Service Temporarily Unavailable",
            "The requested service is currently experiencing issues. Please try again later.",
            region
        );
        
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Health check endpoint for the gateway itself
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Gateway Service");
        response.put("timestamp", LocalDateTime.now());
        response.put("message", "Gateway is running normally");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Extract region from exchange attributes
     */
    private RegionPartition getRegionFromExchange(ServerWebExchange exchange) {
        Object regionAttr = exchange.getAttributes().get("user.region");
        return regionAttr instanceof RegionPartition ? (RegionPartition) regionAttr : RegionPartition.US;
    }

    /**
     * Create standardized fallback response
     */
    private Map<String, Object> createFallbackResponse(String title, String message, RegionPartition region) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", true);
        response.put("title", title);
        response.put("message", message);
        response.put("timestamp", LocalDateTime.now());
        response.put("region", region.getCode());
        response.put("statusCode", HttpStatus.SERVICE_UNAVAILABLE.value());
        response.put("suggestion", "Please try again in a few moments or contact support if the issue persists.");
        
        return response;
    }
} 