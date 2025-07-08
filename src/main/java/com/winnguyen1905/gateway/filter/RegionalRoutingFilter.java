package com.winnguyen1905.gateway.filter;

import com.winnguyen1905.gateway.common.RegionPartition;
import com.winnguyen1905.gateway.service.RegionCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Enhanced Global filter that intelligently detects user's region using multiple factors:
 * 1. Cached IP-region mapping from Redis (primary)
 * 2. User preferences from JWT token
 * 3. Session-based region caching
 * 4. Accept-Language header analysis
 * 5. Custom region headers
 * 6. IP-based geolocation (fallback)
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RegionalRoutingFilter implements GlobalFilter, Ordered {

    private final RegionCacheService regionCacheService;

    // Headers to add to downstream requests
    public static final String REGION_HEADER = "X-User-Region";
    public static final String CLIENT_IP_HEADER = "X-Client-IP";
    public static final String REGION_CODE_HEADER = "X-Region-Code";
    public static final String REGION_TIMEZONE_HEADER = "X-Region-Timezone";
    public static final String REGION_DETECTION_METHOD_HEADER = "X-Region-Detection-Method";
    
    // Header constants
    
    // Language to region mapping
    private static final Map<String, RegionPartition> LANGUAGE_REGION_MAPPING = createLanguageRegionMapping();
    
    private static Map<String, RegionPartition> createLanguageRegionMapping() {
        Map<String, RegionPartition> mapping = new HashMap<>();
        mapping.put("en-US", RegionPartition.US);
        mapping.put("en-CA", RegionPartition.US);
        mapping.put("es-MX", RegionPartition.US);
        mapping.put("en-GB", RegionPartition.EU);
        mapping.put("de-DE", RegionPartition.EU);
        mapping.put("fr-FR", RegionPartition.EU);
        mapping.put("it-IT", RegionPartition.EU);
        mapping.put("es-ES", RegionPartition.EU);
        mapping.put("zh-CN", RegionPartition.ASIA);
        mapping.put("ja-JP", RegionPartition.ASIA);
        mapping.put("ko-KR", RegionPartition.ASIA);
        mapping.put("en-AU", RegionPartition.ASIA);
        mapping.put("en-SG", RegionPartition.ASIA);
        return Map.copyOf(mapping);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        
        // Skip regional detection for health checks and actuator endpoints
        if (shouldSkipRegionalDetection(request)) {
            return chain.filter(exchange);
        }

        // Extract session ID and client IP
        String sessionId = extractSessionId(request);
        String clientIp = extractClientIp(request);
        
        log.debug("Processing request from IP: {} with session: {} for path: {}", 
                 clientIp, sessionId, request.getPath().value());

        return detectUserRegion(request, sessionId, clientIp)
                .flatMap(regionContext -> {
                    // Add regional headers to request
                    ServerHttpRequest mutatedRequest = addRegionalHeaders(request, clientIp, regionContext);
                    
                    // Add region context to exchange attributes for use by other filters
                    exchange.getAttributes().put("user.region", regionContext.region());
                    exchange.getAttributes().put("region.detection.method", regionContext.detectionMethod());
                    exchange.getAttributes().put("client.ip", clientIp);
                    exchange.getAttributes().put("session.id", sessionId);
                    
                    log.info("Detected region {} via {} for IP {}, routing to regional services", 
                             regionContext.region().getCode(), regionContext.detectionMethod(), clientIp);
                    
                    // Cache region for session
                    if (sessionId != null) {
                        regionCacheService.cacheSessionRegion(sessionId, regionContext.region()).subscribe();
                    }
                    
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .doOnError(error -> log.error("Error in regional routing filter: {}", error.getMessage()));
    }

    /**
     * Intelligent region detection using multiple factors with priority order
     */
    private Mono<RegionContext> detectUserRegion(ServerHttpRequest request, String sessionId, String clientIp) {
        // Priority 1: Explicit region header (highest priority)
        String explicitRegion = request.getHeaders().getFirst("X-Preferred-Region");
        if (isValidRegionCode(explicitRegion)) {
            return Mono.just(new RegionContext(RegionPartition.fromCode(explicitRegion), "EXPLICIT_HEADER"));
        }

        // Priority 2: Cached IP-region mapping from Redis (primary detection method)
        return regionCacheService.getRegionForIp(clientIp)
                .map(region -> new RegionContext(region, "IP_CACHE"))
                .switchIfEmpty(
                    // Priority 3: User preferences from JWT token
                    extractRegionFromJWT(request)
                            .map(region -> new RegionContext(region, "JWT_PREFERENCE"))
                )
                .switchIfEmpty(
                    // Priority 4: Session-based cached region
                    regionCacheService.getCachedSessionRegion(sessionId)
                            .map(region -> new RegionContext(region, "SESSION_CACHE"))
                )
                .switchIfEmpty(
                    // Priority 5: Accept-Language header analysis
                    extractRegionFromLanguage(request)
                            .map(region -> new RegionContext(region, "LANGUAGE_HEADER"))
                )
                .defaultIfEmpty(new RegionContext(RegionPartition.US, "DEFAULT_FALLBACK"));
    }

    /**
     * Extract region from JWT token user preferences
     */
    private Mono<RegionPartition> extractRegionFromJWT(ServerHttpRequest request) {
        // For now, try to extract from custom headers until Spring Security is configured
        String jwtRegion = request.getHeaders().getFirst("X-JWT-Region");
        if (isValidRegionCode(jwtRegion)) {
            return Mono.just(RegionPartition.fromCode(jwtRegion));
        }
        
        String jwtCountry = request.getHeaders().getFirst("X-JWT-Country");
        if (jwtCountry != null && !jwtCountry.trim().isEmpty()) {
            return Mono.just(RegionPartition.fromCountry(jwtCountry));
        }
        
        return Mono.empty();
    }

    /**
     * Extract region from Accept-Language header
     */
    private Mono<RegionPartition> extractRegionFromLanguage(ServerHttpRequest request) {
        return Mono.fromCallable(() -> {
            List<String> acceptLanguageHeaders = request.getHeaders().get(HttpHeaders.ACCEPT_LANGUAGE);
            if (acceptLanguageHeaders == null || acceptLanguageHeaders.isEmpty()) {
                return null;
            }

            String acceptLanguage = acceptLanguageHeaders.get(0);
            List<Locale.LanguageRange> languageRanges = Locale.LanguageRange.parse(acceptLanguage);
            
            for (Locale.LanguageRange range : languageRanges) {
                String languageTag = range.getRange();
                RegionPartition region = LANGUAGE_REGION_MAPPING.get(languageTag);
                if (region != null) {
                    return region;
                }
                
                // Try with just the language part (e.g., "en" from "en-US")
                if (languageTag.contains("-")) {
                    String language = languageTag.split("-")[0];
                    for (Map.Entry<String, RegionPartition> entry : LANGUAGE_REGION_MAPPING.entrySet()) {
                        if (entry.getKey().startsWith(language + "-")) {
                            return entry.getValue();
                        }
                    }
                }
            }
            return null;
        });
    }



    /**
     * Extract session ID from request
     */
    private String extractSessionId(ServerHttpRequest request) {
        // Try to get session ID from various sources
        String sessionId = request.getHeaders().getFirst("X-Session-ID");
        if (sessionId != null) {
            return sessionId;
        }
        
        // Try to extract from cookies
        List<String> cookies = request.getHeaders().get("Cookie");
        if (cookies != null) {
            for (String cookie : cookies) {
                if (cookie.contains("SESSIONID=")) {
                    return cookie.substring(cookie.indexOf("SESSIONID=") + 10).split(";")[0];
                }
            }
        }
        
        return null;
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
    private ServerHttpRequest addRegionalHeaders(ServerHttpRequest request, String clientIp, RegionContext regionContext) {
        return request.mutate()
                .header(REGION_HEADER, regionContext.region().getDisplayName())
                .header(CLIENT_IP_HEADER, clientIp)
                .header(REGION_CODE_HEADER, regionContext.region().getCode())
                .header(REGION_TIMEZONE_HEADER, regionContext.region().getTimeZone())
                .header(REGION_DETECTION_METHOD_HEADER, regionContext.detectionMethod())
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
                "/favicon.ico",
                "/admin",
                "/internal"
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

    /**
     * Validate if region code is valid
     */
    private boolean isValidRegionCode(String regionCode) {
        if (regionCode == null || regionCode.trim().isEmpty()) {
            return false;
        }
        try {
            RegionPartition.fromCode(regionCode);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public int getOrder() {
        // Execute early in the filter chain, but after authentication filters
        return -50;
    }

    /**
     * Context record for region detection result
     */
    private record RegionContext(RegionPartition region, String detectionMethod) {}
} 