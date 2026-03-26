# Secure LLM Gateway (AI Security Project)

## Features
- Prompt Injection Protection
- Secure RAG Pipeline
- Output Filtering (Data Leakage Prevention)
- JWT Authentication
- AI Red Teaming with Promptfoo

## Tech Stack
Spring Boot, Java, OpenAI, Docker, Promptfoo

## Security Coverage
OWASP LLM Top 10

## How to Run
1. mvn clean install
2. docker build -t secure-llm .
3. docker run -p 8080:8080 secure-llm

## Promptfoo Red Teaming
1. Install promptfoo: `npm install -g @promptfoo/cli` or `npx @promptfoo/cli`
2. Start app locally: `docker run -p 8080:8080 secure-llm`
3. Run tests: `npx promptfoo run redteam/promptfoo.yml`
4. If you want a report: `npx promptfoo run redteam/promptfoo.yml --reporter junit`

