package com.winnguyen1905.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for Keycloak integration.
 * Maps keycloak.* properties from application.yaml
 */
@Data
@Component
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {
    
    private String serverUrl = "http://localhost:8087";
    private String realm = "master";
    private String clientId = "admin-cli";
    private String clientSecret = "";
    private boolean directAccessGrantsEnabled = true;
    private String tokenIntrospectEndpoint;
    private Admin admin = new Admin();

    @Data
    public static class Admin {
        private String username = "admin";
        private String password = "admin";
    }
}
