package com.secure.llm.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ModelRegistry stores available model configurations and metadata.
 * This paper component can be extended to integrate runtime model selection.
 */
@Slf4j
@Component
public class ModelRegistry {

    private final Map<String, ModelInfo> models = new ConcurrentHashMap<>();

    public ModelRegistry() {
        // OpenAI models
        registerModel(new ModelInfo("gpt-4o", "OpenAI GPT-4o", "openai", "gpt-4o", List.of("text", "chat")));
        registerModel(new ModelInfo("gpt-4-turbo", "OpenAI GPT-4 Turbo", "openai", "gpt-4-turbo-preview", List.of("text", "chat")));
        
        // Azure OpenAI models
        registerModel(new ModelInfo("azure-gpt", "Azure OpenAI GPT", "azure", "gpt-4o", List.of("text", "chat")));
        
        // Bedrock models - Claude
        registerModel(new ModelInfo("claude-3-sonnet", "Claude 3 Sonnet (Bedrock)", "bedrock", "anthropic.claude-3-sonnet-20240229-v1:0", List.of("text", "chat")));
        registerModel(new ModelInfo("claude-3-opus", "Claude 3 Opus (Bedrock)", "bedrock", "anthropic.claude-3-opus-20240229-v1:0", List.of("text", "chat")));
        registerModel(new ModelInfo("claude-3-haiku", "Claude 3 Haiku (Bedrock)", "bedrock", "anthropic.claude-3-haiku-20240307-v1:0", List.of("text", "chat")));
        
        // Bedrock models - Meta Llama
        registerModel(new ModelInfo("llama-2-70b", "Llama 2 70B (Bedrock)", "bedrock", "meta.llama2-70b-chat-v1", List.of("text", "chat")));
        
        // Bedrock models - Mistral
        registerModel(new ModelInfo("mistral-7b", "Mistral 7B (Bedrock)", "bedrock", "mistral.mistral-7b-instruct-v0:2", List.of("text", "chat")));
    }

    public void registerModel(ModelInfo modelInfo) {
        models.put(modelInfo.getId(), modelInfo);
        log.info("Registered model {}", modelInfo.getId());
    }

    public ModelInfo getModel(String id) {
        return models.get(id);
    }

    public List<ModelInfo> listModels() {
        return List.copyOf(models.values());
    }

    @Data
    @AllArgsConstructor
    public static class ModelInfo {
        private String id;
        private String name;
        private String provider;
        private String engine;
        private List<String> supportedModes;
    }
}
