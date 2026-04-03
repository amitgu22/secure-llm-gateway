package com.secure.llm.service;

/**
 * Abstract interface for LLM provider implementations
 * Supports multiple backends: OpenAI, Azure, Bedrock, etc.
 */
public interface LLMProvider {
    
    /**
     * Invoke LLM with the given prompt
     * 
     * @param prompt The complete prompt including system context
     * @return The LLM response
     */
    String invoke(String prompt);
    
    /**
     * Get the provider name
     * @return Provider name (e.g., "openai", "azure", "bedrock")
     */
    String getProviderName();
    
    /**
     * Check if this provider is available
     * @return true if configured and ready to use
     */
    boolean isAvailable();
}
