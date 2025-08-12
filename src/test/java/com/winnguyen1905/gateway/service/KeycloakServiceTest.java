package com.winnguyen1905.gateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.winnguyen1905.gateway.config.KeycloakProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class KeycloakServiceTest {

    @Mock
    private WebClient webClient;

    private KeycloakService keycloakService;
    private ObjectMapper objectMapper;
    private KeycloakProperties keycloakProperties;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        keycloakProperties = new KeycloakProperties();
        keycloakProperties.setServerUrl("http://localhost:8087");
        keycloakProperties.setRealm("master");
        keycloakProperties.setClientId("admin-cli");
        keycloakProperties.setClientSecret("");
        
        keycloakService = new KeycloakService(webClient, objectMapper, keycloakProperties);
    }

    @Test
    void testDecodeTokenPayload() {
        // Create a mock JWT token
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().encodeToString("{\"sub\":\"user123\",\"preferred_username\":\"testuser\",\"email\":\"test@example.com\"}".getBytes());
        String signature = Base64.getUrlEncoder().encodeToString("signature".getBytes());
        String token = header + "." + payload + "." + signature;

        Mono<JsonNode> result = keycloakService.decodeTokenPayload(token);

        StepVerifier.create(result)
                .assertNext(jsonNode -> {
                    assertThat(jsonNode.get("sub").asText()).isEqualTo("user123");
                    assertThat(jsonNode.get("preferred_username").asText()).isEqualTo("testuser");
                    assertThat(jsonNode.get("email").asText()).isEqualTo("test@example.com");
                })
                .verifyComplete();
    }

    @Test
    void testDecodeTokenPayloadWithBearerPrefix() {
        // Create a mock JWT token with Bearer prefix
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().encodeToString("{\"sub\":\"user123\",\"preferred_username\":\"testuser\"}".getBytes());
        String signature = Base64.getUrlEncoder().encodeToString("signature".getBytes());
        String token = "Bearer " + header + "." + payload + "." + signature;

        Mono<JsonNode> result = keycloakService.decodeTokenPayload(token);

        StepVerifier.create(result)
                .assertNext(jsonNode -> {
                    assertThat(jsonNode.get("sub").asText()).isEqualTo("user123");
                    assertThat(jsonNode.get("preferred_username").asText()).isEqualTo("testuser");
                })
                .verifyComplete();
    }

    @Test
    void testDecodeTokenPayloadInvalidFormat() {
        String invalidToken = "invalid.token";

        Mono<JsonNode> result = keycloakService.decodeTokenPayload(invalidToken);

        StepVerifier.create(result)
                .expectError(RuntimeException.class)
                .verify();
    }

    @Test
    void testExtractUserRoles() {
        // Create a mock JWT token with roles
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().encodeToString(
                "{\"sub\":\"user123\",\"realm_access\":{\"roles\":[\"USER\",\"ADMIN\",\"default-roles-master\",\"offline_access\"]}}".getBytes()
        );
        String signature = Base64.getUrlEncoder().encodeToString("signature".getBytes());
        String token = header + "." + payload + "." + signature;

        Mono<String> result = keycloakService.extractUserRoles(token);

        StepVerifier.create(result)
                .assertNext(roles -> {
                    assertThat(roles).contains("USER");
                    assertThat(roles).contains("ADMIN");
                    assertThat(roles).doesNotContain("default-roles-master");
                    assertThat(roles).doesNotContain("offline_access");
                })
                .verifyComplete();
    }
}
