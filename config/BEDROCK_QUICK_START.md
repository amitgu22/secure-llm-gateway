# Bedrock Integration - Quick Start

## Installation

### 1. Build the project
```bash
mvn clean install
```

### 2. Set AWS Credentials
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### 3. Configure application.properties
```properties
bedrock.enabled=true
bedrock.region=us-east-1
bedrock.model-id=anthropic.claude-3-sonnet-20240229-v1:0
llm.default-provider=bedrock
llm.default-model=claude-3-sonnet
```

### 4. Run the application
```bash
mvn spring-boot:run
```

## API Examples

### Basic Request (Uses Default Model)
```bash
curl -X POST http://localhost:8080/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "What is prompt injection and how do we prevent it?"}'
```

### Request with Specific Bedrock Model
```bash
curl -X POST http://localhost:8080/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "Explain RAG architecture", "model": "claude-3-opus"}'
```

### Request with OpenAI Fallback
```bash
curl -X POST http://localhost:8080/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"input": "What is zero-shot learning?", "model": "gpt-4o"}'
```

## Available Models

| Model ID | Provider | Description |
|----------|----------|-------------|
| gpt-4o | OpenAI | Latest OpenAI model |
| claude-3-opus | Bedrock | Most capable Claude 3 model |
| claude-3-sonnet | Bedrock | Balanced Claude 3 model (recommended) |
| claude-3-haiku | Bedrock | Fastest Claude 3 model |
| llama-2-70b | Bedrock | Meta's Llama 2 70B |
| mistral-7b | Bedrock | Mistral's 7B model |

## Response Format

```json
{
  "response": "The AI assistant's response filtered for security...",
  "model": "claude-3-sonnet",
  "success": true
}
```

## Architecture

```
AIController
    ↓
PromptSanitizer (validates input)
    ↓
RagService (retrieves safe context documents)
    ↓
LLMService (routes to appropriate provider)
    ↓
    ├→ BedrockService (AWS Bedrock)
    └→ OpenAIService (OpenAI/Azure)
    ↓
OutputFilter (filters response for data leakage)
```

## Troubleshooting

### Issue: "AccessDeniedException from AWS Bedrock"
**Solution:** Verify IAM permissions include `bedrock-runtime:InvokeModel`

### Issue: "Bedrock service not initialized"
**Solution:** Ensure `bedrock.enabled=true` and credentials are set

### Issue: Model not available in region
**Solution:** Check [supported models by region](https://docs.aws.amazon.com/bedrock/latest/userguide/what-is-bedrock.html#models-supported)

## Security Best Practices

✅ **Always enabled:**
- Prompt Sanitizer (PromptSanitizer.java)
- Output Filter (OutputFilter.java)
- JWT Authentication (SecurityConfig.java)

✅ **Store credentials securely:**
- Use IAM roles in production
- Never commit credentials to git
- Rotate access keys regularly

✅ **Monitor & audit:**
- Enable CloudWatch logging
- Review AWS API calls
- Monitor rate limits

## Next Steps

1. **Test with different models** - Compare responses across Claude, Llama, and Mistral
2. **Implement cost monitoring** - Track Bedrock API costs
3. **Add load balancing** - Route requests across multiple models
4. **Integrate with existing RAG** - Use Bedrock for semantic search
5. **Run red team tests** - Use promptfoo to test for vulnerabilities

## Related Documentation
- [BEDROCK_INTEGRATION.md](./BEDROCK_INTEGRATION.md) - Detailed Bedrock configuration
- [service/README.md](../service/README.md) - Service architecture
- [security/README.md](../security/README.md) - Security features
