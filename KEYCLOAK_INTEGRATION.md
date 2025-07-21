# Keycloak JWT Integration for Gateway Service

This document describes the complete Keycloak JWT authentication and authorization setup for the Gateway Service.

## 🎯 **Features Implemented**

### **Authentication**
- ✅ JWT validation using Keycloak public keys
- ✅ Automatic token relay to downstream services
- ✅ Token introspection and validation
- ✅ Support for Keycloak realm roles

### **Authorization**
- ✅ Path-based access control
- ✅ Role-based authorization (ADMIN, MANAGER, USER)
- ✅ HTTP method-specific permissions
- ✅ Custom security rules per service endpoint

### **User Context Propagation**
- ✅ Extract user information from JWT
- ✅ Add user context headers for downstream services
- ✅ Regional routing with user context
- ✅ Comprehensive logging and debugging

## 🔧 **Configuration Overview**

### **1. Dependencies Added**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

### **2. OAuth2 Configuration**
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8081/realms/myrealm
          jwk-set-uri: http://localhost:8081/realms/myrealm/protocol/openid-connect/certs
```

### **3. Token Relay**
```yaml
spring:
  cloud:
    gateway:
      default-filters:
        - TokenRelay  # Automatically forwards JWT to downstream services
```

## 🔐 **Security Rules**

### **Public Endpoints (No Authentication)**
- `/actuator/**` - Health checks and monitoring
- `/fallback/**` - Circuit breaker fallbacks  
- `/health`, `/info` - Basic health endpoints
- `GET /api/v1/products/**` - Public product browsing
- `GET /api/v1/inventories/**` - Public inventory viewing
- `GET /api/v1/promotions/**` - Public promotions
- `GET /api/v1/discounts/**` - Public discounts
- `/api/v1/auth/login` - Authentication endpoint
- `/api/v1/auth/register` - Registration endpoint
- `/api/v1/auth/refresh` - Token refresh

### **USER Role Required**
- `GET|POST|PUT|DELETE /api/v1/cart/**` - Shopping cart operations
- `GET|POST /api/v1/orders/**` - Order viewing and creation
- `/api/v1/payments/**` - Payment operations
- `/api/v1/shipping/**` - Shipping operations

### **MANAGER Role Required**
- `POST|PUT /api/v1/products/**` - Product management
- `POST|PUT /api/v1/promotions/**` - Promotion management
- `PUT /api/v1/orders/**` - Order management

### **ADMIN Role Required**
- `/admin/**` - Administrative endpoints
- `DELETE /api/v1/**` - Deletion operations (with MANAGER)

## 🏷️ **User Context Headers**

The gateway automatically adds these headers to downstream requests:

| Header | Description | Example |
|--------|-------------|---------|
| `X-User-ID` | User's unique identifier (sub claim) | `f47ac10b-58cc-4372-a567-0e02b2c3d479` |
| `X-User-Email` | User's email address | `john.doe@example.com` |
| `X-User-Preferred-Username` | User's preferred username | `johndoe` |
| `X-User-Name` | User's full name | `John Doe` |
| `X-User-Roles` | Comma-separated roles | `USER,MANAGER` |
| `Authorization` | Original JWT Bearer token | `Bearer eyJhbGciOiJSUzI1NiIs...` |

## 🎭 **Keycloak Role Mapping**

### **JWT Structure**
Keycloak places roles in the `realm_access.roles` claim:
```json
{
  "realm_access": {
    "roles": ["user", "manager", "offline_access", "uma_authorization"]
  },
  "preferred_username": "johndoe",
  "email": "john.doe@example.com",
  "given_name": "John",
  "family_name": "Doe"
}
```

### **Role Conversion**
The `KeycloakRealmRoleConverter` converts Keycloak roles to Spring Security authorities:
- `user` → `ROLE_USER`
- `manager` → `ROLE_MANAGER`  
- `admin` → `ROLE_ADMIN`

**Filtered Roles**: Default Keycloak roles are filtered out:
- `default-*` roles
- `offline_access`
- `uma_authorization`

## 🚀 **Testing the Integration**

### **1. Get JWT Token from Keycloak**
```bash
# Get access token
curl -X POST \
  http://localhost:8081/realms/myrealm/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=johndoe&password=password&client_id=your-client-id&client_secret=your-client-secret'
```

### **2. Access Protected Endpoints**
```bash
# Access protected endpoint with JWT
curl -H "Authorization: Bearer <your-jwt-token>" \
     http://localhost:9191/api/v1/orders

# Check user context headers (if you have debug endpoint)
curl -H "Authorization: Bearer <your-jwt-token>" \
     -v http://localhost:9191/api/v1/cart
```

### **3. Test Role-Based Access**
```bash
# Admin-only endpoint (requires ADMIN role)
curl -H "Authorization: Bearer <admin-jwt-token>" \
     -X DELETE http://localhost:9191/api/v1/products/123

# Manager endpoint (requires MANAGER role)  
curl -H "Authorization: Bearer <manager-jwt-token>" \
     -X POST http://localhost:9191/api/v1/products \
     -H "Content-Type: application/json" \
     -d '{"name":"New Product"}'
```

## 🔧 **Downstream Service Configuration**

For downstream services to validate JWT independently, add to each service:

### **Dependencies**
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

### **Configuration**
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8081/realms/myrealm
```

### **Security Configuration**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .build();
    }
}
```

## 🚨 **Error Handling**

### **401 Unauthorized**
```json
{
    "error": "Unauthorized",
    "message": "Authentication required to access this resource",
    "timestamp": "2024-01-15T10:30:00Z",
    "path": "/api/v1/orders"
}
```

### **403 Forbidden**
```json
{
    "error": "Forbidden", 
    "message": "Insufficient privileges to access this resource",
    "timestamp": "2024-01-15T10:30:00Z",
    "path": "/api/v1/admin/users"
}
```

## 🔍 **Debugging**

### **Enable Debug Logging**
```yaml
logging:
  level:
    com.winnguyen1905.gateway.config.SecurityConfig: DEBUG
    com.winnguyen1905.gateway.filter.JwtExtractionFilter: DEBUG
    org.springframework.security: DEBUG
    org.springframework.security.oauth2: DEBUG
```

### **JWT Decoder Debugging**
```yaml
logging:
  level:
    org.springframework.security.oauth2.jwt: DEBUG
```

## ⚡ **Performance Considerations**

1. **JWT Validation Caching**: Spring automatically caches JWK sets
2. **Token Relay**: Minimal overhead for forwarding tokens
3. **Role Extraction**: Efficient single-pass role conversion
4. **Regional Headers**: Added during existing filter processing

## 🔄 **Filter Execution Order**

1. **Security Filter** (-100): JWT validation and authentication
2. **JWT Extraction Filter** (-40): Extract user context
3. **Regional Routing Filter** (-50): Regional detection and routing
4. **Rate Limiting Filter** (0): Apply rate limits
5. **Circuit Breaker Filter** (100): Circuit breaker logic

## 📋 **Checklist for Setup**

- [ ] Keycloak server running on port 8081
- [ ] Realm `myrealm` configured in Keycloak
- [ ] Client configured with appropriate scopes
- [ ] Users created with required roles (`user`, `manager`, `admin`)
- [ ] Gateway service configured with correct Keycloak URLs
- [ ] Downstream services configured for JWT validation
- [ ] Test endpoints with various user roles

## 🎯 **Key Benefits**

1. **Single Point of Authentication**: Centralized JWT validation at gateway
2. **Automatic Token Relay**: Seamless JWT forwarding to services  
3. **Role-Based Authorization**: Granular access control per endpoint
4. **User Context Propagation**: Rich user information for downstream services
5. **Regional Awareness**: Combined with regional routing capabilities
6. **Production Ready**: Comprehensive error handling and logging

---

**✅ Your gateway is now fully secured with Keycloak JWT authentication and authorization!** 