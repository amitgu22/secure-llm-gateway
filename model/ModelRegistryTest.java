package com.secure.llm.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ModelRegistryTest {

    private ModelRegistry registry;

    @BeforeEach
    public void setUp() {
        registry = new ModelRegistry();
    }

    @Test
    public void testListModelsNotEmpty() {
        assertFalse(registry.listModels().isEmpty());
    }

    @Test
    public void testGetModelExisting() {
        ModelRegistry.ModelInfo model = registry.getModel("gpt-4o");
        assertNotNull(model);
        assertEquals("gpt-4o", model.getId());
    }

    @Test
    public void testRegisterModel() {
        ModelRegistry.ModelInfo newModel = new ModelRegistry.ModelInfo("my-gpt", "My GPT", "openai", "gpt-4o", java.util.List.of("chat"));
        registry.registerModel(newModel);

        ModelRegistry.ModelInfo fromRegistry = registry.getModel("my-gpt");
        assertNotNull(fromRegistry);
        assertEquals("My GPT", fromRegistry.getName());
    }
}
