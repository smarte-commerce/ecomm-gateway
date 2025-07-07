package com.winnguyen1905.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Enhanced API Gateway Service with Regional Routing Capabilities.
 * 
 * Features:
 * - IP-based region detection and routing
 * - Regional database connection routing
 * - Redis-based region caching
 * - Circuit breaker patterns
 * - Rate limiting per region/IP
 * - Graceful fallback handling
 */
@SpringBootApplication
@EnableDiscoveryClient
public class GatewayServiceApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(GatewayServiceApplication.class, args);
	}
}
