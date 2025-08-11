package com.winnguyen1905.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.winnguyen1905.gateway.config.KeycloakProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Base64;

/**
 * Service for interacting with Keycloak APIs for JWT validation and user
 * information extraction.
 * Provides methods to validate tokens, decode JWT payloads, and retrieve user
 * information.
 */
@Service
@Slf4j
public class KeycloakService {

  private final WebClient webClient;
  private final ObjectMapper objectMapper;
  private final KeycloakProperties keycloakProperties;

  public KeycloakService(WebClient webClient, ObjectMapper objectMapper, KeycloakProperties keycloakProperties) {
    this.webClient = webClient;
    this.objectMapper = objectMapper;
    this.keycloakProperties = keycloakProperties;
  }

  /**
   * Validate JWT token using Keycloak's token introspection endpoint
   */
  public Mono<JsonNode> validateToken(String token) {
    log.debug("Validating token with Keycloak");

    String introspectUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
        + "/protocol/openid-connect/token/introspect";

    MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
    formData.add("token", token);
    formData.add("client_id", keycloakProperties.getClientId());
    if (keycloakProperties.getClientSecret() != null && !keycloakProperties.getClientSecret().isEmpty()) {
      formData.add("client_secret", keycloakProperties.getClientSecret());
    }

    return webClient.post()
        .uri(introspectUrl)
        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
        .body(BodyInserters.fromFormData(formData))
        .retrieve()
        .bodyToMono(String.class)
        .map(response -> {
          try {
            JsonNode jsonNode = objectMapper.readTree(response);
            log.debug("Token validation response: {}", jsonNode);
            return jsonNode;
          } catch (Exception e) {
            log.error("Error parsing token validation response", e);
            throw new RuntimeException("Failed to parse token validation response", e);
          }
        })
        .doOnError(error -> log.error("Error validating token with Keycloak", error));
  }

  /**
   * Decode JWT token payload without validation (for extracting claims)
   */
  public Mono<JsonNode> decodeTokenPayload(String token) {
    try {
      // Remove Bearer prefix if present
      if (token.startsWith("Bearer ")) {
        token = token.substring(7);
      }

      // Split the JWT token
      String[] chunks = token.split("\\.");
      if (chunks.length != 3) {
        return Mono.error(new IllegalArgumentException("Invalid JWT token format"));
      }

      // Decode the payload (second part)
      Base64.Decoder decoder = Base64.getUrlDecoder();
      String payload = new String(decoder.decode(chunks[1]));

      JsonNode jsonNode = objectMapper.readTree(payload);
      log.debug("Decoded JWT payload: {}", jsonNode);

      return Mono.just(jsonNode);
    } catch (Exception e) {
      log.error("Error decoding JWT token", e);
      return Mono.error(new RuntimeException("Failed to decode JWT token", e));
    }
  }

  /**
   * Get user info from Keycloak using the access token
   */
  public Mono<JsonNode> getUserInfo(String token) {
    log.debug("Getting user info from Keycloak");

    String userInfoUrl = keycloakProperties.getServerUrl() + "/realms/" + keycloakProperties.getRealm()
        + "/protocol/openid-connect/userinfo";

    return webClient.get()
        .uri(userInfoUrl)
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
        .retrieve()
        .bodyToMono(String.class)
        .map(response -> {
          try {
            JsonNode jsonNode = objectMapper.readTree(response);
            log.debug("User info response: {}", jsonNode);
            return jsonNode;
          } catch (Exception e) {
            log.error("Error parsing user info response", e);
            throw new RuntimeException("Failed to parse user info response", e);
          }
        })
        .doOnError(error -> log.error("Error getting user info from Keycloak", error));
  }

  /**
   * Check if token is active by validating with Keycloak
   */
  public Mono<Boolean> isTokenActive(String token) {
    return validateToken(token)
        .map(validationResponse -> validationResponse.path("active").asBoolean())
        .onErrorReturn(false);
  }

  /**
   * Extract user roles from token validation response or JWT payload
   */
  public Mono<String> extractUserRoles(String token) {
    return decodeTokenPayload(token)
        .map(payload -> {
          JsonNode realmAccess = payload.path("realm_access");
          if (realmAccess.isObject() && realmAccess.has("roles")) {
            JsonNode roles = realmAccess.get("roles");
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
              return rolesStr.toString();
            }
          }
          return "";
        })
        .onErrorReturn("");
  }
}
