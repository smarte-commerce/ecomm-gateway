package com.winnguyen1905.gateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.winnguyen1905.gateway.service.KeycloakService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

/**
 * Global filter to extract JWT information using Keycloak API and add user
 * context headers
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
  public static final String CLIENT_ID_HEADER = "X-Client-ID";
  public static final String TOKEN_EXP_HEADER = "X-Token-Exp";
  public static final String TOKEN_IAT_HEADER = "X-Token-Iat";

  private final KeycloakService keycloakService;

  public JwtExtractionFilter(KeycloakService keycloakService) {
    this.keycloakService = keycloakService;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();
    String path = request.getURI().getPath();

    // Skip JWT extraction for public endpoints
    if (isPublicEndpoint(path)) {
      log.debug("Skipping JWT extraction for public endpoint: {}", path);
      return chain.filter(exchange);
    }

    String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      log.debug("No valid Authorization header found");
      return handleUnauthorized(exchange);
    }

    String token = authHeader.substring(7);

    // Validate token with Keycloak and extract user info
    return keycloakService.validateToken(token)
        .flatMap(validationResponse -> {
          if (!validationResponse.path("active").asBoolean()) {
            log.debug("Token is not active");
            return handleUnauthorized(exchange);
          }

          // Extract user information from validation response or decode JWT
          return extractUserInfo(token, validationResponse)
              .flatMap(userInfo -> {
                // Add user information to request headers
                ServerHttpRequest modifiedRequest = addUserHeaders(request, userInfo);
                ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(modifiedRequest)
                    .build();

                return chain.filter(modifiedExchange);
              });
        })
        .onErrorResume(error -> {
          log.error("Error processing JWT token", error);
          return handleUnauthorized(exchange);
        });
  }

  private Mono<JsonNode> extractUserInfo(String token, JsonNode validationResponse) {
    // Try to get user info from validation response first
    if (validationResponse.has("sub") && validationResponse.has("preferred_username")) {
      return Mono.just(validationResponse);
    }

    // Fallback to decoding JWT payload
    return keycloakService.decodeTokenPayload(token);
  }

  private ServerHttpRequest addUserHeaders(ServerHttpRequest request, JsonNode userInfo) {
    ServerHttpRequest.Builder builder = request.mutate();

    // Add user ID
    if (userInfo.has("sub")) {
      builder.header(USER_ID_HEADER, userInfo.get("sub").asText());
    }

    // Add username
    if (userInfo.has("preferred_username")) {
      builder.header(USER_PREFERRED_USERNAME_HEADER, userInfo.get("preferred_username").asText());
    }

    // Add email
    if (userInfo.has("email")) {
      builder.header(USER_EMAIL_HEADER, userInfo.get("email").asText());
    }

    // Add full name
    String fullName = buildFullName(userInfo);
    if (fullName != null) {
      builder.header(USER_NAME_HEADER, fullName);
    }

    // Add roles
    if (userInfo.has("realm_access") && userInfo.get("realm_access").has("roles")) {
      JsonNode roles = userInfo.get("realm_access").get("roles");
      if (roles.isArray()) {
        StringBuilder rolesStr = new StringBuilder();
        for (JsonNode role : roles) {
          String roleName = role.asText();
          // Filter out default Keycloak roles
          if (!roleName.startsWith("default-") &&
              !roleName.equals("offline_access") &&
              !roleName.equals("uma_authorization")) {
            if (rolesStr.length() > 0) {
              rolesStr.append(",");
            }
            rolesStr.append(roleName);
          }
        }
        builder.header(USER_ROLES_HEADER, rolesStr.toString());
      }
    }

    // Add client ID
    if (userInfo.has("azp")) {
      builder.header(CLIENT_ID_HEADER, userInfo.get("azp").asText());
    }

    // Add token expiration
    if (userInfo.has("exp")) {
      builder.header(TOKEN_EXP_HEADER, userInfo.get("exp").asText());
    }

    // Add issued at
    if (userInfo.has("iat")) {
      builder.header(TOKEN_IAT_HEADER, userInfo.get("iat").asText());
    }

    log.debug("Added user headers to request");
    return builder.build();
  }

  /**
   * Build full name from first and last name in JWT claims
   */
  private String buildFullName(JsonNode userInfo) {
    String firstName = userInfo.has("given_name") ? userInfo.get("given_name").asText() : null;
    String lastName = userInfo.has("family_name") ? userInfo.get("family_name").asText() : null;

    if (firstName != null && lastName != null) {
      return firstName + " " + lastName;
    } else if (firstName != null) {
      return firstName;
    } else if (lastName != null) {
      return lastName;
    }
    return null;
  }

  private boolean isPublicEndpoint(String path) {
    List<String> publicPaths = Arrays.asList(
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/oauth2",
        "/health",
        "/actuator",
        "/swagger-ui",
        "/v3/api-docs",
        "/fallback");

    return publicPaths.stream().anyMatch(path::startsWith);
  }

  private Mono<Void> handleUnauthorized(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
  }

  @Override
  public int getOrder() {
    // Execute after security context is populated but before regional routing
    return -40;
  }
}
