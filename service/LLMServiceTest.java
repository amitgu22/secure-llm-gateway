package com.secure.llm.service;

import com.secure.llm.model.ModelRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for LLMService with multi-provider support
 */
@ExtendWith(MockitoExtension.class)
public class LLMServiceTest {

    @Mock
    private OpenAIService openAIService;

    @Mock
    private Optional<BedrockService> bedrockServiceOptional;

    @Mock
    private ModelRegistry modelRegistry;

    @InjectMocks
    private LLMService llmService;

    private List<String> contextDocs;

    @BeforeEach
    void setUp() {
        contextDocs = List.of("Sample documentation", "Security best practices");
    }

    @Test
    void testCallLLMWithDefaultModel() {
        String userInput = "What is prompt injection?";
        String expectedResponse = "[OpenAI Response] ...";

        when(openAIService.invoke(anyString())).thenReturn(expectedResponse);
        when(modelRegistry.getModel(anyString())).thenReturn(null); // Falls back to default

        String response = llmService.callLLM(userInput, contextDocs);

        assertNotNull(response, "Response should not be null");
        verify(openAIService, times(1)).invoke(anyString());
    }

    @Test
    void testCallLLMWithBedrockModel() {
        String userInput = "Explain secure coding";
        String modelId = "claude-3-sonnet";
        BedrockService bedrockService = mock(BedrockService.class);
        String expectedResponse = "[Bedrock Response] Claude 3 Sonnet response";

        when(bedrockService.isAvailable()).thenReturn(true);
        when(bedrockService.invoke(anyString())).thenReturn(expectedResponse);
        when(bedrockServiceOptional.isPresent()).thenReturn(true);
        when(bedrockServiceOptional.get()).thenReturn(bedrockService);

        ModelRegistry.ModelInfo modelInfo = new ModelRegistry.ModelInfo(
                modelId,
                "Claude 3 Sonnet",
                "bedrock",
                "anthropic.claude-3-sonnet-20240229-v1:0",
                List.of("text", "chat")
        );
        when(modelRegistry.getModel(modelId)).thenReturn(modelInfo);

        String response = llmService.callLLM(userInput, contextDocs, modelId);

        assertNotNull(response, "Response should not be null");
        verify(bedrockService, times(1)).invoke(anyString());
    }

    @Test
    void testCallLLMFallsBackToOpenAIWhenBedrockUnavailable() {
        String userInput = "Test prompt";
        String modelId = "claude-3-sonnet";
        String expectedResponse = "[OpenAI Fallback Response]";

        when(bedrockServiceOptional.isPresent()).thenReturn(false);
        when(openAIService.invoke(anyString())).thenReturn(expectedResponse);

        ModelRegistry.ModelInfo modelInfo = new ModelRegistry.ModelInfo(
                modelId,
                "Claude 3 Sonnet",
                "bedrock",
                "anthropic.claude-3-sonnet-20240229-v1:0",
                List.of("text", "chat")
        );
        when(modelRegistry.getModel(modelId)).thenReturn(modelInfo);

        String response = llmService.callLLM(userInput, contextDocs, modelId);

        assertNotNull(response, "Response should not be null");
        verify(openAIService, times(1)).invoke(anyString());
    }

    @Test
    void testCallLLMIncludesSystemPrompt() {
        String userInput = "What is XSS?";
        String expectedResponse = "[Response]";

        when(openAIService.invoke(anyString())).thenReturn(expectedResponse);
        when(modelRegistry.getModel(anyString())).thenReturn(null);

        llmService.callLLM(userInput, contextDocs);

        verify(openAIService).invoke(argThat(prompt ->
                prompt.contains("You are a secure AI assistant") &&
                prompt.contains(userInput)
        ));
    }

    @Test
    void testCallLLMIncludesContext() {
        String userInput = "Explain the context";
        String expectedContext = "Sample documentation";
        String expectedResponse = "[Response]";

        when(openAIService.invoke(anyString())).thenReturn(expectedResponse);
        when(modelRegistry.getModel(anyString())).thenReturn(null);

        llmService.callLLM(userInput, contextDocs);

        verify(openAIService).invoke(argThat(prompt ->
                prompt.contains(expectedContext)
        ));
    }
}
