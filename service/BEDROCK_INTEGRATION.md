# Bedrock Integration Guide

## Overview
This project now supports AWS Bedrock for LLM inference in addition to OpenAI and Azure OpenAI.

## Bedrock Models Supported

### Claude Models (Recommended)
- **claude-3-opus** - Most capable, best for complex tasks
- **claude-3-sonnet** - Balanced performance and cost (recommended)
- **claude-3-haiku** - Fastest, lowest cost

### Other Models
- **llama-2-70b** - Meta's Llama 2 70B model
- **mistral-7b** - Mistral's 7B instruction-tuned model

## Configuration

### 1. Enable Bedrock
Add to `application.properties`:

```properties
# Enable Bedrock
bedrock.enabled=true

# AWS Configuration
bedrock.region=us-east-1
bedrock.access-key-id=${AWS_ACCESS_KEY_ID}
bedrock.secret-access-key=${AWS_SECRET_ACCESS_KEY}

# Model Configuration
bedrock.model-id=anthropic.claude-3-sonnet-20240229-v1:0
bedrock.max-tokens=1024
bedrock.temperature=0.7
bedrock.top-p=0.9

# Default LLM provider
llm.default-provider=bedrock
llm.default-model=claude-3-sonnet
```

### 2. AWS Credentials
Option A: Environment Variables (recommended)
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

Option B: AWS Configuration File (~/.aws/credentials)
```
[default]
aws_access_key_id = your_key
aws_secret_access_key = your_secret
```

### 3. Maven Dependency
The project includes AWS SDK dependencies. Ensure `pom.xml` has:

```xml
<!-- AWS Bedrock SDK -->
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>bedrockruntime</artifactId>
    <version>2.25.0</version>
</dependency>
```

## Usage

### Using Default Model
```java
String response = llmService.callLLM(userInput, contextDocs);
```

### Selecting Specific Model
```java
String response = llmService.callLLM(userInput, contextDocs, "claude-3-opus");
```

### Listing Available Models
```java
List<ModelRegistry.ModelInfo> models = modelRegistry.listModels();
models.forEach(m -> System.out.println(m.getId() + ": " + m.getName()));
```

## API Endpoint

```bash
POST /ai/chat
Content-Type: application/json

{
  "input": "What is prompt injection?",
  "model": "claude-3-sonnet"  // optional, uses default if not specified
}
```

## Pricing & Limits

### Claude 3 Pricing (as of 2024)
- **Sonnet**: Input $3/million tokens, Output $15/million tokens
- **Opus**: Input $15/million tokens, Output $75/million tokens  
- **Haiku**: Input $0.25/million tokens, Output $1.25/million tokens

### Rate Limits
- Default: 100 requests/minute per model
- Contact AWS for higher limits

## Security Considerations

1. **Sensitive Data**: Bedrock requests may be logged by AWS. Avoid sending PII in prompts.
2. **Prompt Injection**: The application already includes PromptSanitizer for mitigation.
3. **Output Filtering**: OutputFilter is applied to all responses regardless of provider.
4. **Credentials**: Never commit AWS credentials to git. Use environment variables or IAM roles.

## Troubleshooting

### "Bedrock service not initialized"
- Check `bedrock.enabled=true` in application.properties
- Verify AWS credentials are set correctly
- Check AWS region configuration

### "Unexpected Bedrock response format"
- Verify model ID is correct
- Check Bedrock model availability in your region
- Review CloudWatch logs in AWS console

### Connection Timeout
- Ensure AWS SDK has network access
- Check IAM permissions for bedrock-runtime:InvokeModel
- Verify region is correct

## Advanced: Multi-Provider Load Balancing

Future enhancements can implement fallback strategies:

```java
// Fallback to OpenAI if Bedrock is unavailable
private String invokeProvider(String provider, String prompt) {
    switch (provider.toLowerCase()) {
        case "bedrock":
            if (bedrockService.isPresent() && bedrockService.get().isAvailable()) {
                return bedrockService.get().invoke(prompt);
            }
            // Fall through to OpenAI
        case "openai":
        default:
            return openAIService.invoke(prompt);
    }
}
```

## References
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Claude 3 Models](https://docs.anthropic.com/claude/reference/models-overview)
- [Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/)
