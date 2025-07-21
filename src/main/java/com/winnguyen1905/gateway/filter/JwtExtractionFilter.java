package com.winnguyen1905.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Global filter to extract JWT information and add user context headers
 * for downstream microservices.
 */
@Component
@Slf4j
public class JwtExtractionFilter implements GlobalFilter, Ordered {

    // Headers to add user information for downstream services
    public static final String USER_ID_HEADER = "X-User-ID";
    public static final String USER_EMAIL_HEADER = "X-User-Email";
    public static final String USER_ROLES_HEADER = "X-User-Roles";
    public static final String USER_PREFERRED_USERNAME_HEADER = "X-User-Preferred-Username";
    public static final String USER_NAME_HEADER = "X-User-Name";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .cast(SecurityContext.class)
                .map(SecurityContext::getAuthentication)
                .cast(JwtAuthenticationToken.class)
                .flatMap(authentication -> {
                    Jwt jwt = authentication.getToken();
                    
                    // Extract user information from JWT
                    String userId = jwt.getClaimAsString("sub");
                    String email = jwt.getClaimAsString("email");
                    String preferredUsername = jwt.getClaimAsString("preferred_username");
                    String firstName = jwt.getClaimAsString("given_name");
                    String lastName = jwt.getClaimAsString("family_name");
                    String fullName = buildFullName(firstName, lastName);
                    
                    // Extract roles
                    List<String> roles = authentication.getAuthorities().stream()
                            .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                            .collect(Collectors.toList());
                    String rolesString = String.join(",", roles);
                    
                    log.debug("Extracting JWT info for user: {} with roles: {}", preferredUsername, rolesString);
                    
                    // Add user context headers to request
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header(USER_ID_HEADER, userId != null ? userId : "")
                            .header(USER_EMAIL_HEADER, email != null ? email : "")
                            .header(USER_PREFERRED_USERNAME_HEADER, preferredUsername != null ? preferredUsername : "")
                            .header(USER_NAME_HEADER, fullName != null ? fullName : "")
                            .header(USER_ROLES_HEADER, rolesString)
                            .build();
                    
                    // Add user context to exchange attributes
                    exchange.getAttributes().put("jwt.user.id", userId);
                    exchange.getAttributes().put("jwt.user.email", email);
                    exchange.getAttributes().put("jwt.user.username", preferredUsername);
                    exchange.getAttributes().put("jwt.user.roles", roles);
                    
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .switchIfEmpty(
                    // No authentication found - proceed without user headers
                    chain.filter(exchange)
                )
                .onErrorResume(error -> {
                    log.debug("No JWT authentication found, proceeding without user context: {}", error.getMessage());
                    return chain.filter(exchange);
                });
    }

    /**
     * Build full name from first and last name
     */
    private String buildFullName(String firstName, String lastName) {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        }
        return null;
    }

    @Override
    public int getOrder() {
        // Execute after security context is populated but before regional routing
        return -40;
    }
} 