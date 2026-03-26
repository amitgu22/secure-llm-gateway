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
        // Example models loaded at startup; override with config or DB as needed.
        registerModel(new ModelInfo("gpt-4o", "OpenAI GPT-4o", "openai", "gpt-4o", List.of("text", "chat")));
        registerModel(new ModelInfo("azure-gpt", "Azure OpenAI GPT", "azure", "gpt-4o", List.of("text", "chat")));
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
