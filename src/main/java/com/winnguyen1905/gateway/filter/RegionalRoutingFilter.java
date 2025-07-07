package com.winnguyen1905.gateway.filter;

import com.winnguyen1905.gateway.common.RegionPartition;
import com.winnguyen1905.gateway.service.GeoLocationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Global filter that detects user's region based on IP address and adds regional context
 * to requests for downstream services.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RegionalRoutingFilter implements GlobalFilter, Ordered {

    private final GeoLocationService geoLocationService;

    // Headers to add to downstream requests
    public static final String REGION_HEADER = "X-User-Region";
    public static final String CLIENT_IP_HEADER = "X-Client-IP";
    public static final String REGION_CODE_HEADER = "X-Region-Code";
    public static final String REGION_TIMEZONE_HEADER = "X-Region-Timezone";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        
        // Skip regional detection for health checks and actuator endpoints
        if (shouldSkipRegionalDetection(request)) {
            return chain.filter(exchange);
        }

        // Extract client IP from various headers
        String clientIp = extractClientIp(request);
        
        log.debug("Processing request from IP: {} for path: {}", clientIp, request.getPath().value());

        return geoLocationService.getRegionFromIp(clientIp)
                .flatMap(region -> {
                    // Add regional headers to request
                    ServerHttpRequest mutatedRequest = addRegionalHeaders(request, clientIp, region);
                    
                    // Add region context to exchange attributes for use by other filters
                    exchange.getAttributes().put("user.region", region);
                    exchange.getAttributes().put("client.ip", clientIp);
                    
                    log.debug("Detected region {} for IP {}, routing to regional services", 
                             region.getCode(), clientIp);
                    
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .doOnError(error -> log.error("Error in regional routing filter: {}", error.getMessage()));
    }

    /**
     * Extract client IP from request headers with fallback chain
     */
    private String extractClientIp(ServerHttpRequest request) {
        // Check X-Forwarded-For header (most common for load balancers)
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (isValidIp(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }

        // Check X-Real-IP header (Nginx proxy)
        String xRealIp = request.getHeaders().getFirst("X-Real-IP");
        if (isValidIp(xRealIp)) {
            return xRealIp.trim();
        }

        // Check CF-Connecting-IP header (Cloudflare)
        String cfConnectingIp = request.getHeaders().getFirst("CF-Connecting-IP");
        if (isValidIp(cfConnectingIp)) {
            return cfConnectingIp.trim();
        }

        // Check X-Cluster-Client-IP header (cluster load balancers)
        String clusterClientIp = request.getHeaders().getFirst("X-Cluster-Client-IP");
        if (isValidIp(clusterClientIp)) {
            return clusterClientIp.trim();
        }

        // Fallback to remote address
        if (request.getRemoteAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }

        return "unknown";
    }

    /**
     * Add regional context headers to the request
     */
    private ServerHttpRequest addRegionalHeaders(ServerHttpRequest request, String clientIp, RegionPartition region) {
        return request.mutate()
                .header(REGION_HEADER, region.getDisplayName())
                .header(CLIENT_IP_HEADER, clientIp)
                .header(REGION_CODE_HEADER, region.getCode())
                .header(REGION_TIMEZONE_HEADER, region.getTimeZone())
                .build();
    }

    /**
     * Check if we should skip regional detection for certain endpoints
     */
    private boolean shouldSkipRegionalDetection(ServerHttpRequest request) {
        String path = request.getPath().value().toLowerCase();
        
        // Skip for health checks, actuator, and internal endpoints
        List<String> skipPaths = List.of(
                "/actuator",
                "/health", 
                "/info",
                "/metrics",
                "/prometheus",
                "/ready",
                "/live",
                "/favicon.ico"
        );
        
        return skipPaths.stream().anyMatch(path::startsWith);
    }

    /**
     * Validate if IP address is not null, empty, or placeholder
     */
    private boolean isValidIp(String ip) {
        return ip != null && 
               !ip.trim().isEmpty() && 
               !"unknown".equalsIgnoreCase(ip) &&
               !"0:0:0:0:0:0:0:1".equals(ip) &&
               !"::1".equals(ip);
    }

    @Override
    public int getOrder() {
        // Execute early in the filter chain, but after authentication filters
        return -50;
    }
} 