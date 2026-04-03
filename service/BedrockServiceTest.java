package com.secure.llm.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure.llm.config.BedrockProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for BedrockService
 */
@ExtendWith(MockitoExtension.class)
public class BedrockServiceTest {

    @Mock
    private BedrockProperties bedrockProperties;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private BedrockService bedrockService;

    @BeforeEach
    void setUp() {
        when(bedrockProperties.isEnabled()).thenReturn(false);
    }

    @Test
    void testServiceDisabledByDefault() {
        assertFalse(bedrockService.isAvailable(), 
                   "Bedrock service should not be available when disabled");
    }

    @Test
    void testGetProviderName() {
        assertEquals("bedrock", bedrockService.getProviderName(), 
                    "Provider name should be 'bedrock'");
    }

    @Test
    void testInvokeWhenNotInitialized() {
        when(bedrockProperties.isEnabled()).thenReturn(false);
        
        assertThrows(IllegalStateException.class, () -> {
            bedrockService.invoke("test prompt");
        }, "Should throw IllegalStateException when not initialized");
    }

    @Test
    void testCloseConnection() {
        // Service should close gracefully even when not initialized
        assertDoesNotThrow(() -> bedrockService.close(), 
                          "Close should not throw exception");
    }
}
