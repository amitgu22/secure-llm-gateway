package com.secure.llm.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.llm.config.BedrockProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelRequest;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelResponse;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Bedrock Service Integration for AWS Bedrock Models
 * 
 * Supports various Bedrock models:
 * - Claude 3 (Anthropic)
 * - Llama 2 (Meta)
 * - Mistral
 * - Titan (Amazon)
 */
@Service
@Slf4j
@RequiredArgsConstructor
@ConditionalOnProperty(name = "bedrock.enabled", havingValue = "true", matchIfMissing = false)
public class BedrockService implements LLMProvider {

    private final BedrockProperties bedrockProperties;
    private final ObjectMapper objectMapper;
    
    private BedrockRuntimeClient bedrockClient;
    private boolean initialized = false;

    @PostConstruct
    public void initialize() {
        if (!bedrockProperties.isEnabled()) {
            log.warn("Bedrock service is disabled");
            return;
        }

        try {
            initializeBedrockClient();
            initialized = true;
            log.info("Bedrock service initialized successfully with region: {}", 
                     bedrockProperties.getRegion());
        } catch (Exception e) {
            log.error("Failed to initialize Bedrock service", e);
            initialized = false;
        }
    }

    private void initializeBedrockClient() {
        bedrockClient = BedrockRuntimeClient.builder()
                .region(Region.of(bedrockProperties.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(
                                bedrockProperties.getAccessKeyId(),
                                bedrockProperties.getSecretAccessKey()
                        )
                ))
                .build();
    }

    /**
     * Invoke Claude 3 model on Bedrock
     */
    public String invokeClaudeModel(String prompt) {
        if (!initialized) {
            throw new IllegalStateException("Bedrock service not initialized");
        }

        try {
            Map<String, Object> claudeRequest = buildClaudeRequest(prompt);
            byte[] requestBody = objectMapper.writeValueAsBytes(claudeRequest);

            InvokeModelRequest request = InvokeModelRequest.builder()
                    .modelId(bedrockProperties.getModelId())
                    .body(software.amazon.awssdk.core.SdkBytes.fromByteArray(requestBody))
                    .build();

            InvokeModelResponse response = bedrockClient.invokeModel(request);
            return parseClaudeResponse(response);

        } catch (Exception e) {
            log.error("Error invoking Claude model on Bedrock", e);
            throw new RuntimeException("Bedrock invocation failed", e);
        }
    }

    /**
     * Build request payload for Claude model
     */
    private Map<String, Object> buildClaudeRequest(String prompt) {
        Map<String, Object> request = new HashMap<>();
        request.put("anthropic_version", "bedrock-2023-06-01");
        request.put("max_tokens", bedrockProperties.getMaxTokens());
        request.put("temperature", bedrockProperties.getTemperature());
        request.put("top_p", bedrockProperties.getTopP());
        
        Map<String, Object> content = new HashMap<>();
        content.put("type", "text");
        content.put("text", prompt);
        
        request.put("messages", List.of(
            Map.of(
                "role", "user",
                "content", List.of(content)
            )
        ));
        
        return request;
    }

    /**
     * Parse Claude response from Bedrock
     */
    private String parseClaudeResponse(InvokeModelResponse response) throws Exception {
        byte[] responseBody = response.body().asByteArray();
        Map<String, Object> responseMap = objectMapper.readValue(responseBody, Map.class);
        
        if (responseMap.containsKey("content")) {
            List<Map<String, Object>> content = (List<Map<String, Object>>) responseMap.get("content");
            if (!content.isEmpty() && content.get(0).containsKey("text")) {
                return (String) content.get(0).get("text");
            }
        }
        
        throw new RuntimeException("Unexpected Bedrock response format");
    }

    @Override
    public String invoke(String prompt) {
        return invokeClaudeModel(prompt);
    }

    @Override
    public String getProviderName() {
        return "bedrock";
    }

    @Override
    public boolean isAvailable() {
        return initialized;
    }

    public void close() {
        if (bedrockClient != null) {
            bedrockClient.close();
            log.info("Bedrock client closed");
        }
    }
}
