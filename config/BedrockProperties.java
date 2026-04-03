package com.secure.llm.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Properties for AWS Bedrock configuration
 * 
 * Usage in application.properties:
 * bedrock.enabled=true
 * bedrock.region=us-east-1
 * bedrock.model-id=anthropic.claude-3-sonnet-20240229-v1:0
 * bedrock.max-tokens=1024
 * bedrock.temperature=0.7
 * bedrock.top-p=0.9
 */
@Component
@ConfigurationProperties(prefix = "bedrock")
@Getter
@Setter
public class BedrockProperties {
    
    private boolean enabled = false;
    private String region = "us-east-1";
    private String accessKeyId = "";
    private String secretAccessKey = "";
    private String modelId = "anthropic.claude-3-sonnet-20240229-v1:0";
    private Integer maxTokens = 1024;
    private Double temperature = 0.7;
    private Double topP = 0.9;
}
