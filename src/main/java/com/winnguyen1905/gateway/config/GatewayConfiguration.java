package com.winnguyen1905.gateway.config;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.TcpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Gateway configuration for regional routing functionality.
 * Configures WebClient, Redis, rate limiting, and other necessary components.
 */
@Configuration
@Slf4j
public class GatewayConfiguration {

    /**
     * WebClient for external API calls (geolocation service)
     */
    @Bean
    public WebClient webClient() {
        TcpClient tcpClient = TcpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .doOnConnected(connection -> {
                    connection.addHandlerLast(new ReadTimeoutHandler(5000, TimeUnit.MILLISECONDS));
                    connection.addHandlerLast(new WriteTimeoutHandler(5000, TimeUnit.MILLISECONDS));
                });

        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(HttpClient.from(tcpClient)))
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024)) // 1MB
                .build();
    }

    /**
     * Reactive Redis template for caching region data
     */
    @Bean
    public ReactiveStringRedisTemplate reactiveStringRedisTemplate(ReactiveRedisConnectionFactory factory) {
        return new ReactiveStringRedisTemplate(factory);
    }

    /**
     * Key resolver for rate limiting based on client IP
     */
    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> {
            String clientIp = exchange.getRequest().getRemoteAddress() != null 
                    ? exchange.getRequest().getRemoteAddress().getAddress().getHostAddress()
                    : "unknown";
            
            log.debug("Rate limiting key for IP: {}", clientIp);
            return Mono.just(clientIp);
        };
    }

    /**
     * Key resolver for rate limiting based on user region
     */
    @Bean
    public KeyResolver regionKeyResolver() {
        return exchange -> {
            Object regionAttr = exchange.getAttributes().get("user.region");
            String region = regionAttr != null ? regionAttr.toString() : "unknown";
            
            log.debug("Rate limiting key for region: {}", region);
            return Mono.just(region);
        };
    }

    /**
     * Global timeout configuration for gateway routes
     */
    @Bean
    public RouteTimeoutConfiguration routeTimeoutConfiguration() {
        return new RouteTimeoutConfiguration();
    }

    /**
     * Configuration class for route timeouts
     */
    public static class RouteTimeoutConfiguration {
        private final Duration connectTimeout = Duration.ofSeconds(5);
        private final Duration responseTimeout = Duration.ofSeconds(30);
        private final Duration readTimeout = Duration.ofSeconds(15);

        public Duration getConnectTimeout() { return connectTimeout; }
        public Duration getResponseTimeout() { return responseTimeout; }
        public Duration getReadTimeout() { return readTimeout; }
    }
} 