package com.winnguyen1905.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.winnguyen1905.gateway.common.RegionPartition;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Set;

/**
 * Service for determining user's geographical region based on IP address.
 * Provides caching and fallback mechanisms for reliable region detection.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class GeoLocationService {

    private final WebClient webClient;
    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Cache TTL for IP region mappings
    private static final Duration CACHE_TTL = Duration.ofHours(24);
    
    // Fallback region for unknown/private IPs
    private static final RegionPartition DEFAULT_REGION = RegionPartition.US;
    
    // Private IP ranges to avoid external API calls
    private static final Set<String> PRIVATE_IP_PREFIXES = Set.of(
        "10.", "172.", "192.168.", "127.", "localhost"
    );

    /**
     * Get region for given IP address with caching
     */
    public Mono<RegionPartition> getRegionFromIp(String ipAddress) {
        if (isPrivateOrInvalidIp(ipAddress)) {
            log.debug("Private or invalid IP detected: {}, using default region", ipAddress);
            return Mono.just(DEFAULT_REGION);
        }

        String cacheKey = "region:ip:" + ipAddress;
        
        return redisTemplate.opsForValue()
                .get(cacheKey)
                .cast(String.class)
                .map(RegionPartition::fromCode)
                .doOnNext(region -> log.debug("Found cached region {} for IP {}", region, ipAddress))
                .switchIfEmpty(detectRegionFromExternalApi(ipAddress)
                        .doOnNext(region -> {
                            log.debug("Detected region {} for IP {}, caching result", region, ipAddress);
                            cacheRegion(cacheKey, region).subscribe();
                        }))
                .doOnError(error -> log.error("Error detecting region for IP {}: {}", ipAddress, error.getMessage()))
                .onErrorReturn(DEFAULT_REGION);
    }

    /**
     * Detect region using external geolocation API
     */
    private Mono<RegionPartition> detectRegionFromExternalApi(String ipAddress) {
        return webClient.get()
                .uri("https://ipwho.is/{ip}", ipAddress)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(this::parseGeoLocationResponse)
                .retryWhen(Retry.backoff(2, Duration.ofSeconds(1))
                        .maxBackoff(Duration.ofSeconds(5)))
                .timeout(Duration.ofSeconds(5))
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorReturn(DEFAULT_REGION);
    }

    /**
     * Parse geolocation API response
     */
    private Mono<RegionPartition> parseGeoLocationResponse(String responseBody) {
        return Mono.fromCallable(() -> {
            try {
                JsonNode root = objectMapper.readTree(responseBody);
                
                // Check if request was successful
                if (!root.path("success").asBoolean(true)) {
                    log.warn("Geolocation API returned unsuccessful response: {}", responseBody);
                    return DEFAULT_REGION;
                }

                String country = root.path("country_code").asText();
                String continent = root.path("continent").asText();
                
                log.debug("Geolocation response - Country: {}, Continent: {}", country, continent);

                // Try to determine region from country first, then continent
                if (country != null && !country.isEmpty()) {
                    return RegionPartition.fromCountry(country);
                } else if (continent != null && !continent.isEmpty()) {
                    return RegionPartition.fromContinent(continent);
                }
                
                return DEFAULT_REGION;
                
            } catch (Exception e) {
                log.error("Error parsing geolocation response: {}", e.getMessage());
                return DEFAULT_REGION;
            }
        });
    }

    /**
     * Cache region result in Redis
     */
    private Mono<Boolean> cacheRegion(String cacheKey, RegionPartition region) {
        return redisTemplate.opsForValue()
                .set(cacheKey, region.getCode(), CACHE_TTL)
                .doOnError(error -> log.warn("Failed to cache region for key {}: {}", cacheKey, error.getMessage()))
                .onErrorReturn(false);
    }

    /**
     * Check if IP is private or invalid
     */
    private boolean isPrivateOrInvalidIp(String ipAddress) {
        if (ipAddress == null || ipAddress.trim().isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            return true;
        }
        
        String cleanIp = ipAddress.trim().toLowerCase();
        return PRIVATE_IP_PREFIXES.stream().anyMatch(cleanIp::startsWith);
    }

    /**
     * Get region from X-Forwarded-For header (for load balancers/proxies)
     */
    public Mono<RegionPartition> getRegionFromForwardedHeader(String forwardedFor) {
        if (forwardedFor == null || forwardedFor.trim().isEmpty()) {
            return Mono.just(DEFAULT_REGION);
        }

        // X-Forwarded-For may contain multiple IPs, first one is usually the client
        String clientIp = forwardedFor.split(",")[0].trim();
        return getRegionFromIp(clientIp);
    }

    /**
     * Bulk region detection for multiple IPs (useful for analytics)
     */
    public Mono<RegionPartition> getRegionFromMultipleIps(String... ipAddresses) {
        for (String ip : ipAddresses) {
            if (!isPrivateOrInvalidIp(ip)) {
                return getRegionFromIp(ip);
            }
        }
        return Mono.just(DEFAULT_REGION);
    }
} 