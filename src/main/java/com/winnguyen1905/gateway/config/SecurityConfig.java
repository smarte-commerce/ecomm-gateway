package com.winnguyen1905.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.lang.NonNull;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Security configuration for Gateway Service with Keycloak JWT validation.
 * Handles authentication, authorization, and role mapping for Keycloak tokens.
 */
@Configuration
@EnableWebFluxSecurity
@Slf4j
public class SecurityConfig {

  private final KeycloakProperties keycloakProperties;

  public SecurityConfig(KeycloakProperties keycloakProperties) {
    this.keycloakProperties = keycloakProperties;
  }

  /**
   * Main security filter chain configuration
   */
  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    return http
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .cors(ServerHttpSecurity.CorsSpec::disable)
        .authorizeExchange(exchanges -> exchanges
            // Public endpoints - no authentication required
            .pathMatchers("/actuator/**", "/fallback/**", "/health", "/info").permitAll()

            // Admin endpoints - admin role required
            .pathMatchers("/admin/**").hasRole("ADMIN")
            .pathMatchers(HttpMethod.DELETE, "/**").hasAnyRole("ADMIN", "MANAGER")

            // Product service endpoints
            .pathMatchers(HttpMethod.GET, "/products/**", "/inventories/**").permitAll()
            .pathMatchers(HttpMethod.POST, "/products/**").hasAnyRole("ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.PUT, "/products/**").hasAnyRole("ADMIN", "MANAGER")

            // Order service endpoints
            .pathMatchers(HttpMethod.GET, "/orders/**").hasAnyRole("USER", "ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.POST, "/orders/**").hasAnyRole("USER", "ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.PUT, "/orders/**").hasAnyRole("ADMIN", "MANAGER")

            // Cart service endpoints
            .pathMatchers(HttpMethod.GET, "/cart/**").hasAnyRole("USER", "ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.POST, "/cart/**").hasAnyRole("USER", "ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.PUT, "/cart/**").hasAnyRole("USER", "ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.DELETE, "/cart/**").hasAnyRole("USER", "ADMIN", "MANAGER")

            // Payment service endpoints
            .pathMatchers("/payments/**").hasAnyRole("USER", "ADMIN", "MANAGER")

            // Promotion service endpoints
            .pathMatchers(HttpMethod.GET, "/promotions/**", "/discounts/**").permitAll()
            .pathMatchers(HttpMethod.POST, "/promotions/**").hasAnyRole("ADMIN", "MANAGER")
            .pathMatchers(HttpMethod.PUT, "/promotions/**").hasAnyRole("ADMIN", "MANAGER")

            // Shipping service endpoints
            .pathMatchers("/shipping/**").hasAnyRole("USER", "ADMIN", "MANAGER")

            // Auth service endpoints - special handling
            .pathMatchers("/auth/login", "/auth/register", "/auth/refresh").permitAll()
            .pathMatchers("/auth/**").authenticated()

            // All other requests require authentication
            .anyExchange().authenticated())
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .jwtDecoder(jwtDecoder())
                .jwtAuthenticationConverter(grantedAuthoritiesExtractor())))
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint(authenticationEntryPoint())
            .accessDeniedHandler(accessDeniedHandler()))
        .build();
  }

  /**
   * JWT Authentication Converter for extracting Keycloak roles
   */
  @Bean
  Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
    JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
    authenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
    return new ReactiveJwtAuthenticationConverterAdapter(authenticationConverter);
  }

  /**
   * Reactive JWT Decoder for Keycloak tokens
   */
  @Bean
  public ReactiveJwtDecoder jwtDecoder() {
    String jwkSetUri = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
        + "/protocol/openid-connect/certs";
    return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
  }

  /**
   * Custom authentication entry point for unauthorized requests
   */
  @Bean
  public ServerAuthenticationEntryPoint authenticationEntryPoint() {
    return (exchange, ex) -> {
      log.warn("Unauthorized access attempt to: {}", exchange.getRequest().getPath().value());

      exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
      exchange.getResponse().getHeaders().add("Content-Type", "application/json");

      String body = """
          {
              "error": "Unauthorized",
              "message": "Authentication required to access this resource",
              "timestamp": "%s",
              "path": "%s"
          }
          """.formatted(java.time.Instant.now(), exchange.getRequest().getPath().value());

      org.springframework.core.io.buffer.DataBuffer buffer = exchange.getResponse().bufferFactory()
          .wrap(body.getBytes());

      return exchange.getResponse().writeWith(Mono.just(buffer));
    };
  }

  /**
   * Custom access denied handler for forbidden requests
   */
  @Bean
  public ServerAccessDeniedHandler accessDeniedHandler() {
    return (exchange, denied) -> {
      log.warn("Access denied for user to: {}", exchange.getRequest().getPath().value());

      exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.FORBIDDEN);
      exchange.getResponse().getHeaders().add("Content-Type", "application/json");

      String body = """
          {
              "error": "Forbidden",
              "message": "Insufficient privileges to access this resource",
              "timestamp": "%s",
              "path": "%s"
          }
          """.formatted(java.time.Instant.now(), exchange.getRequest().getPath().value());

      org.springframework.core.io.buffer.DataBuffer buffer = exchange.getResponse().bufferFactory()
          .wrap(body.getBytes());

      return exchange.getResponse().writeWith(Mono.just(buffer));
    };
  }

  /**
   * Keycloak realm role converter to extract roles from JWT token
   */
  public static class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(@NonNull Jwt jwt) {
      log.debug("Converting JWT claims to authorities for user: {}", jwt.getClaimAsString("preferred_username"));

      // Extract realm access roles
      Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
      if (realmAccess == null) {
        log.debug("No realm_access found in JWT");
        return List.of();
      }

      @SuppressWarnings("unchecked")
      List<String> roles = (List<String>) realmAccess.get("roles");
      if (roles == null) {
        log.debug("No roles found in realm_access");
        return List.of();
      }

      List<GrantedAuthority> authorities = roles.stream()
          .filter(role -> !role.startsWith("default-") && !role.equals("offline_access")
              && !role.equals("uma_authorization"))
          .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
          .collect(Collectors.toList());

      log.debug("Extracted authorities: {}", authorities);
      return authorities;
    }
  }
}
