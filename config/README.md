# SecurityConfig - Comprehensive Security Configuration

## Overview

The enhanced `SecurityConfig` provides enterprise-grade security for the Secure LLM Gateway using Spring Security 6.x with OAuth2/JWT authentication, fine-grained authorization, and comprehensive security headers.

## Key Improvements Over Original

### 1. **JWT Validation**
- **Original**: Basic OAuth2 resource server setup
- **Improved**: Multi-layer JWT validation with issuer, audience, and timestamp verification
- **Implementation**: Uses `DelegatingOAuth2TokenValidator` with custom validators

### 2. **CORS Configuration**
- **Original**: Not configured
- **Improved**: Comprehensive CORS with allowed origins, methods, headers, and credentials policy
- **Benefit**: Prevents unauthorized cross-origin requests

### 3. **CSRF Protection**
- **Original**: CSRF disabled entirely (`csrf().disable()`)
- **Improved**: CSRF enabled with session-based token repository
- **Security**: Token validation for state-changing operations (POST, PUT, DELETE)

### 4. **Security Headers**
- **Original**: None
- **Improved**: Industry-standard security headers
  - HSTS (HTTP Strict Transport Security)
  - CSP (Content Security Policy)
  - X-Frame-Options (Clickjacking protection)
  - X-Content-Type-Options (MIME sniffing prevention)
  - Referrer-Policy (Information leakage prevention)
  - Permissions-Policy (Feature restrictions)

### 5. **Authorization Model**
- **Original**: Basic authenticated/unauthenticated split
- **Improved**: Role-based access control (RBAC) with hierarchy
  - USER: Access to AI query endpoints
  - SECURITY_ADMIN: Security audit and monitoring
  - ADMIN: Full management access
  - REDTEAM: Restricted red team testing

### 6. **Exception Handling**
- **Original**: Default error responses
- **Improved**: Custom JSON error responses for:
  - Authentication failures (401)
  - Authorization failures (403)
  - Structured error format with message details

### 7. **Session Management**
- **Original**: Not explicitly configured
- **Improved**: Stateless session policy (ideal for API)
  - No persistent sessions on server
  - JWT handles authentication state
  - Session fixation protection enabled

## Security Features

### Authentication Endpoints
```
GET  /api/health              - Public health check
GET  /api/metrics             - Public metrics
GET  /swagger-ui/**           - Public API documentation

GET  /api/ai/**               - Requires @Authenticated
POST /api/ai/**               - Requires @Authenticated
```

### Authorization Hierarchy
```
PUT  /api/ai/**               - Requires @ADMIN
DELETE /api/ai/**             - Requires @ADMIN
GET  /api/security/**         - Requires @SECURITY_ADMIN
GET  /api/redteam/**          - Requires @REDTEAM

All other endpoints          - Denied by default
```

### Role Hierarchy
```
ADMIN
  ├─ SECURITY_ADMIN
  │   ├─ USER
  └─ ADMIN rights

SECURITY_ADMIN
  ├─ USER

REDTEAM
  ├─ USER
```

## Configuration

### application.properties
```properties
# JWT Configuration
jwt.issuer=http://localhost:8080
jwt.audience=secure-llm-gateway
jwt.secret=your-secret-key-change-in-production
jwt.expiration=3600000

# CORS Configuration
cors.allowed-origins=http://localhost:3000,http://localhost:3001
cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
cors.max-age=3600
```

### pom.xml Dependencies
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>
```

## Security Headers Explained

### Strict-Transport-Security (HSTS)
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- Enforces HTTPS for 1 year
- Prevents SSL stripping attacks

### X-Frame-Options
```
X-Frame-Options: DENY
```
- Prevents clickjacking attacks
- Page cannot be framed by any origin

### X-Content-Type-Options
```
X-Content-Type-Options: nosniff
```
- Prevents MIME type sniffing
- Browser must respect declared Content-Type

### Content-Security-Policy (CSP)
```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```
- Restricts resource loading
- Prevents inline script execution (customizable)

### Referrer-Policy
```
Referrer-Policy: strict-no-referrer
```
- Never sends referrer information
- Prevents information leakage

## JWT Authentication Flow

```
1. Client obtains JWT from Authorization Server
2. Client sends request with: Authorization: Bearer <JWT>
3. SecurityFilterChain intercepts request
4. JwtDecoder validates JWT
   a. Signature verification
   b. Issuer validation
   c. Audience validation
   d. Timestamp/expiry validation
5. JwtAuthenticationConverter extracts:
   a. User ID from 'sub' claim
   b. Roles from 'roles' claim
6. Spring Security creates Authentication object
7. Authorization rules applied based on roles
8. Request routed to controller
```

## JWT Payload Example

```json
{
  "iss": "http://localhost:8080",
  "sub": "user123",
  "aud": "secure-llm-gateway",
  "exp": 1234567890,
  "iat": 1234567800,
  "roles": ["user", "security-admin"],
  "email": "user@example.com"
}
```

## CORS Configuration

### Preflight Request (OPTIONS)
```
OPTIONS /api/ai/query
Origin: http://localhost:3000
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type,Authorization
```

### Preflight Response
```
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Max-Age: 3600
```

## Usage Examples

### Protecting an Endpoint with Annotations
```java
@RestController
@RequestMapping("/api/ai")
public class AiController {
    
    @GetMapping("/query")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> query(@RequestBody QueryRequest request) {
        // Endpoint automatically protected by Spring Security
        return ResponseEntity.ok(llmService.query(request));
    }
    
    @DeleteMapping("/model/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteModel(@PathVariable String id) {
        modelService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
```

### Getting Current User in Controller
```java
@GetMapping("/profile")
public ResponseEntity<?> getProfile(
    @AuthenticationPrincipal org.springframework.security.oauth2.jwt.Jwt jwt) {
    
    String userId = jwt.getSubject();
    List<String> roles = jwt.getClaimAsStringList("roles");
    
    return ResponseEntity.ok(Map.of(
        "userId", userId,
        "roles", roles
    ));
}
```

## Testing

### Running Security Tests
```bash
mvn test -Dtest=SecurityConfigTest
```

### Key Test Scenarios
- Public endpoints accessibility
- Authentication requirement enforcement
- Authorization role checks
- Security header presence
- CORS validation
- CSRF protection
- Error handling/format
- Session management (stateless)

## Production Checklist

- [ ] Change `jwt.secret` to strong random value
- [ ] Set `jwt.issuer` to production authorization server
- [ ] Update `cors.allowed-origins` with actual frontend domains
- [ ] Enable HTTPS (set `server.ssl.*` properties)
- [ ] Configure rate limiting for authentication endpoints
- [ ] Set up JWT token rotation policy
- [ ] Enable audit logging
- [ ] Configure log aggregation
- [ ] Set appropriate token expiration times
- [ ] Review and adjust security headers for your use case

## Advanced Customization

### Disable CSRF for Specific Endpoints
```java
.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/webhook/**")
)
```

### Add Custom Token Validators
```java
private OAuth2TokenValidator<Jwt> customValidator() {
    return (token) -> {
        if (/* custom check */) {
            return OAuth2TokenValidator.Result.success();
        }
        return OAuth2TokenValidator.Result.failure(...);
    };
}
```

### Implement Custom Authorization Logic
```java
@Bean
public AuthorizationManager<HttpServletRequest> authorizationManager() {
    return (authentication, request) -> {
        // Custom authorization logic
        return new AuthorizationDecision(true);
    };
}
```

## Security Best Practices Applied

1. ✅ Defense in depth (multiple layers)
2. ✅ Principle of least privilege (deny by default)
3. ✅ Secure by default (CSRF enabled, CORS restrictive)
4. ✅ Security headers (modern mitigations)
5. ✅ Token validation (multiple checks)
6. ✅ Stateless authentication (API scalability)
7. ✅ Role-based access (granular control)
8. ✅ Error handling (no information leakage)

## References

- Spring Security 6.x Documentation
- OAuth 2.0 RFC 6749
- OpenID Connect Core 1.0
- OWASP Security Headers
- NIST Cybersecurity Framework
