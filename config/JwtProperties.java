package com.secure.llm.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * JWT Properties Configuration
 * Binds to application.properties with 'jwt.' prefix
 */
@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
    
    private String issuer;
    private String audience;
    private String secret;
    private long expiration;
    private String publicKey;
    private String privateKey;
    
    // Advanced JWT settings
    private String algorithm = "HS256";
    private List<String> supportedAlgorithms = List.of("HS256", "RS256", "ES256");
    private boolean validateCertificate = true;
    private int clockSkewSeconds = 60;
}
