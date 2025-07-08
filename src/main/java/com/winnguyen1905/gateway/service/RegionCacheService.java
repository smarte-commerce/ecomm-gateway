package com.winnguyen1905.gateway.service;

import com.winnguyen1905.gateway.common.RegionPartition;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Service for managing IP-to-region caching in Redis.
 * This centralizes all region detection and caching logic at the gateway level.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class RegionCacheService {

    private final ReactiveStringRedisTemplate redisTemplate;
    private final GeoLocationService geoLocationService;

    // Cache configuration
    private static final String IP_REGION_PREFIX = "ip:region:";
    private static final String SESSION_REGION_PREFIX = "session:region:";
    private static final Duration IP_REGION_TTL = Duration.ofHours(24); // 24 hours for IP-region mapping
    private static final Duration SESSION_REGION_TTL = Duration.ofHours(6); // 6 hours for session-based region

    /**
     * Get region for IP address with comprehensive caching strategy
     */
    public Mono<RegionPartition> getRegionForIp(String clientIp) {
        if (isPrivateOrInvalidIp(clientIp)) {
            log.debug("Private or invalid IP detected: {}, using default region", clientIp);
            return Mono.just(RegionPartition.US);
        }

        String cacheKey = getIpRegionKey(clientIp);
        
        return redisTemplate.opsForValue()
                .get(cacheKey)
                .map(RegionPartition::fromCode)
                .doOnNext(region -> log.debug("Found cached region {} for IP {}", region.getCode(), clientIp))
                .switchIfEmpty(
                    // Cache miss - detect region and cache it
                    geoLocationService.getRegionFromIp(clientIp)
                            .flatMap(region -> cacheIpRegion(clientIp, region)
                                    .thenReturn(region))
                            .doOnNext(region -> log.info("Detected and cached new region {} for IP {}", region.getCode(), clientIp))
                )
                .onErrorResume(error -> {
                    log.error("Error getting region for IP {}: {}", clientIp, error.getMessage());
                    return Mono.just(RegionPartition.US); // Fallback to US
                });
    }

    /**
     * Cache IP-to-region mapping
     */
    public Mono<Boolean> cacheIpRegion(String clientIp, RegionPartition region) {
        if (isPrivateOrInvalidIp(clientIp)) {
            return Mono.just(false);
        }

        String cacheKey = getIpRegionKey(clientIp);
        
        return redisTemplate.opsForValue()
                .set(cacheKey, region.getCode(), IP_REGION_TTL)
                .doOnSuccess(success -> {
                    if (success) {
                        log.debug("Successfully cached region {} for IP {} with TTL {}", 
                                region.getCode(), clientIp, IP_REGION_TTL);
                    } else {
                        log.warn("Failed to cache region {} for IP {}", region.getCode(), clientIp);
                    }
                })
                .onErrorResume(error -> {
                    log.error("Error caching region for IP {}: {}", clientIp, error.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Get cached region for IP (without detection fallback)
     */
    public Mono<RegionPartition> getCachedRegionForIp(String clientIp) {
        if (isPrivateOrInvalidIp(clientIp)) {
            return Mono.empty();
        }

        String cacheKey = getIpRegionKey(clientIp);
        
        return redisTemplate.opsForValue()
                .get(cacheKey)
                .map(RegionPartition::fromCode)
                .doOnNext(region -> log.debug("Retrieved cached region {} for IP {}", region.getCode(), clientIp))
                .onErrorResume(error -> {
                    log.error("Error retrieving cached region for IP {}: {}", clientIp, error.getMessage());
                    return Mono.empty();
                });
    }

    /**
     * Cache session-based region for faster subsequent lookups
     */
    public Mono<Boolean> cacheSessionRegion(String sessionId, RegionPartition region) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return Mono.just(false);
        }

        String cacheKey = getSessionRegionKey(sessionId);
        
        return redisTemplate.opsForValue()
                .set(cacheKey, region.getCode(), SESSION_REGION_TTL)
                .doOnSuccess(success -> {
                    if (success) {
                        log.debug("Successfully cached session region {} for session {} with TTL {}", 
                                region.getCode(), sessionId, SESSION_REGION_TTL);
                    }
                })
                .onErrorResume(error -> {
                    log.error("Error caching session region for session {}: {}", sessionId, error.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Get cached session region
     */
    public Mono<RegionPartition> getCachedSessionRegion(String sessionId) {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return Mono.empty();
        }

        String cacheKey = getSessionRegionKey(sessionId);
        
        return redisTemplate.opsForValue()
                .get(cacheKey)
                .map(RegionPartition::fromCode)
                .doOnNext(region -> log.debug("Retrieved cached session region {} for session {}", region.getCode(), sessionId))
                .onErrorResume(error -> {
                    log.error("Error retrieving cached session region for session {}: {}", sessionId, error.getMessage());
                    return Mono.empty();
                });
    }

    /**
     * Bulk cache multiple IP-region mappings (useful for batch operations)
     */
    public Mono<Long> bulkCacheIpRegions(java.util.Map<String, RegionPartition> ipRegionMap) {
        if (ipRegionMap == null || ipRegionMap.isEmpty()) {
            return Mono.just(0L);
        }

        // Filter out private IPs and prepare Redis operations
        java.util.Map<String, String> cacheMap = ipRegionMap.entrySet().stream()
                .filter(entry -> !isPrivateOrInvalidIp(entry.getKey()))
                .collect(java.util.stream.Collectors.toMap(
                    entry -> getIpRegionKey(entry.getKey()),
                    entry -> entry.getValue().getCode()
                ));

        if (cacheMap.isEmpty()) {
            return Mono.just(0L);
        }

        return redisTemplate.opsForValue()
                .multiSet(cacheMap)
                .then(
                    // Set TTL for each key
                    reactor.core.publisher.Flux.fromIterable(cacheMap.keySet())
                            .flatMap(key -> redisTemplate.expire(key, IP_REGION_TTL))
                            .count()
                )
                .doOnNext(count -> log.info("Bulk cached {} IP-region mappings", count))
                .onErrorResume(error -> {
                    log.error("Error in bulk caching IP-region mappings: {}", error.getMessage());
                    return Mono.just(0L);
                });
    }

    /**
     * Invalidate cached region for IP (useful for admin operations)
     */
    public Mono<Boolean> invalidateIpRegion(String clientIp) {
        if (isPrivateOrInvalidIp(clientIp)) {
            return Mono.just(false);
        }

        String cacheKey = getIpRegionKey(clientIp);
        
        return redisTemplate.delete(cacheKey)
                .map(deleted -> deleted > 0)
                .doOnNext(deleted -> {
                    if (deleted) {
                        log.info("Invalidated cached region for IP {}", clientIp);
                    }
                })
                .onErrorResume(error -> {
                    log.error("Error invalidating cached region for IP {}: {}", clientIp, error.getMessage());
                    return Mono.just(false);
                });
    }

    /**
     * Get cache statistics for monitoring
     */
    public Mono<CacheStats> getCacheStats() {
        return redisTemplate.scan(org.springframework.data.redis.core.ScanOptions.scanOptions()
                .match(IP_REGION_PREFIX + "*")
                .count(100)
                .build())
                .count()
                .zipWith(
                    redisTemplate.scan(org.springframework.data.redis.core.ScanOptions.scanOptions()
                            .match(SESSION_REGION_PREFIX + "*")
                            .count(100)
                            .build())
                            .count()
                )
                .map(tuple -> new CacheStats(tuple.getT1(), tuple.getT2()))
                .onErrorReturn(new CacheStats(0L, 0L));
    }

    // Helper methods
    private String getIpRegionKey(String ip) {
        return IP_REGION_PREFIX + ip;
    }

    private String getSessionRegionKey(String sessionId) {
        return SESSION_REGION_PREFIX + sessionId;
    }

    private boolean isPrivateOrInvalidIp(String ip) {
        if (ip == null || ip.trim().isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            return true;
        }
        
        String cleanIp = ip.trim().toLowerCase();
        return cleanIp.startsWith("10.") || 
               cleanIp.startsWith("172.") || 
               cleanIp.startsWith("192.168.") || 
               cleanIp.startsWith("127.") || 
               cleanIp.equals("localhost") ||
               cleanIp.equals("0:0:0:0:0:0:0:1") ||
               cleanIp.equals("::1");
    }

    /**
     * Cache statistics record
     */
    public record CacheStats(Long ipRegionCacheSize, Long sessionRegionCacheSize) {}
} 