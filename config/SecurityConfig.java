package com.secure.llm.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchical.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

/**
 * Comprehensive Security Configuration for Secure LLM Gateway
 * 
 * Features:
 * - JWT-based OAuth2 resource server authentication
 * - CORS configuration with fine-grained control
 * - Security headers (HSTS, CSP, X-Frame-Options, etc.)
 * - CSRF protection with token-based approach
 * - Role-based access control (RBAC)
 * - Session management with stateless policy
 * - Password encoding with BCrypt
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
    securedEnabled = true,
    jsr250Enabled = true,
    prePostEnabled = true
)
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${jwt.issuer:http://localhost:8080}")
    private String jwtIssuer;

    @Value("${jwt.audience:secure-llm-gateway}")
    private String jwtAudience;

    @Value("${cors.allowed-origins:http://localhost:3000}")
    private String allowedOrigins;

    @Value("${cors.allowed-methods:GET,POST,PUT,DELETE,OPTIONS}")
    private String allowedMethods;

    @Value("${cors.max-age:3600}")
    private long corsMaxAge;

    /**
     * Main security filter chain configuration
     * Configures authentication, authorization, and security headers
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            // CSRF Protection: Enable for state-changing operations
            .csrf(csrf -> csrf
                .csrfTokenRepository(
                    new org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository()
                )
                .ignoringRequestMatchers(
                    "/api/health",
                    "/api/metrics"
                )
            )
            
            // CORS Configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Session Management: Stateless for API
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionFixationProtection(
                    org.springframework.security.config.web.servlet.SecurityContextConfigurer.SessionFixationProtectionStrategy.MIGRATE_SESSION
                )
            )
            
            // Exception Handling
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(jwtAuthenticationEntryPoint())
                .accessDeniedHandler(jwtAccessDeniedHandler())
            )
            
            // Authorization Rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/api/health", "/api/metrics", "/api/docs/**").permitAll()
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
                
                // LLM Gateway endpoints - require authentication
                .requestMatchers(HttpMethod.POST, "/api/ai/**").authenticated()
                .requestMatchers(HttpMethod.GET, "/api/ai/**").authenticated()
                
                // Management/Admin endpoints
                .requestMatchers(HttpMethod.DELETE, "/api/ai/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT, "/api/ai/**").hasRole("ADMIN")
                
                // Security endpoints
                .requestMatchers("/api/security/**").hasRole("SECURITY_ADMIN")
                
                // Red team testing endpoints (restricted access)
                .requestMatchers("/api/redteam/**").hasRole("REDTEAM")
                
                // Catch all - deny
                .anyRequest().denyAll()
            )
            
            // Security Headers
            .headers(headers -> headers
                .xssProtection(xss -> xss.and().headerValue("1; mode=block"))
                .contentTypeOptions()
                .cacheControl()
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .preload(true)
                    .maxAgeInSeconds(31536000) // 1 year
                )
                .referrerPolicy(ref -> ref
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_NO_REFERRER)
                )
                .frameOptions(frame -> frame.deny())
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
                )
                .permissionsPolicy(permissions -> permissions
                    .policy("geolocation=(), microphone=(), camera=()")
                )
            )
            
            // OAuth2 Resource Server with JWT
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            
            .build();
    }

    /**
     * JWT Decoder with validation
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(
            jwtIssuer + "/oauth/jwks"
        ).build();

        OAuth2TokenValidator<Jwt> withIssuer = new JwtIssuerValidator(jwtIssuer);
        OAuth2TokenValidator<Jwt> withAudience = new JwtClaimValidator<>(
            "aud",
            aud -> aud instanceof java.util.List list && list.contains(jwtAudience)
        );
        OAuth2TokenValidator<Jwt> withClockSkew = new JwtTimestampValidator();

        jwtDecoder.setJwtValidator(
            new DelegatingOAuth2TokenValidator<>(
                withIssuer,
                withAudience,
                withClockSkew
            )
        );

        return jwtDecoder;
    }

    /**
     * JWT Authentication Converter - extracts authorities from JWT claims
     */
    @Bean
    public org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter 
        jwtAuthenticationConverter() {
        
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        
        // Extract roles from 'roles' claim in JWT
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = jwt.getClaimAsStringList("roles");
            
            if (authorities == null) {
                return Collections.emptyList();
            }
            
            return authorities.stream()
                .map(role -> new org.springframework.security.core.authority
                    .SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(java.util.stream.Collectors.toList());
        });
        
        // Use 'sub' claim as principal name
        converter.setPrincipalClaimName("sub");
        
        return converter;
    }

    /**
     * CORS Configuration
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        configuration.setAllowedHeaders(Arrays.asList(
            "Content-Type",
            "Authorization",
            "X-Request-ID",
            "X-API-Key"
        ));
        configuration.setExposedHeaders(Arrays.asList(
            "X-Total-Count",
            "X-Page-Number",
            "X-Page-Size"
        ));
        configuration.setAllowCredentials(false); // Stateless API
        configuration.setMaxAge(corsMaxAge);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }

    /**
     * Password Encoder - BCrypt with configurable strength
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Strength 12 for production
    }

    /**
     * Custom JWT Authentication Entry Point
     */
    @Bean
    public org.springframework.security.web.AuthenticationEntryPoint jwtAuthenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(org.springframework.http.HttpStatus.UNAUTHORIZED.value());
            
            JwtException jwtException = (JwtException) authException.getCause();
            String message = jwtException != null ? jwtException.getMessage() : "Unauthorized";
            
            response.getWriter().write(
                String.format(
                    "{\"error\": \"Unauthorized\", \"message\": \"%s\"}",
                    message.replace("\"", "\\\"")
                )
            );
        };
    }

    /**
     * Custom JWT Access Denied Handler
     */
    @Bean
    public org.springframework.security.web.access.AccessDeniedHandler jwtAccessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(org.springframework.http.HttpStatus.FORBIDDEN.value());
            
            response.getWriter().write(
                String.format(
                    "{\"error\": \"Forbidden\", \"message\": \"%s\"}",
                    accessDeniedException.getMessage().replace("\"", "\\\"")
                )
            );
        };
    }

    /**
     * Role Hierarchy - allows ADMIN to have all USER permissions
     */
    @Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy(
            "ROLE_ADMIN > ROLE_SECURITY_ADMIN\n" +
            "ROLE_SECURITY_ADMIN > ROLE_USER\n" +
            "ROLE_REDTEAM > ROLE_USER"
        );
        return hierarchy;
    }
}
