package com.secure.llm.security;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class OutputFilter {

    private static final List<String> BLOCKED = List.of(
        "api_key",
        "password",
        "internal prompt",
        "secret"
    );

    public String filter(String response) {
        if (response == null || response.isBlank()) {
            return response;
        }

        String lower = response.toLowerCase();

        for (String b : BLOCKED) {
            if (lower.contains(b)) {
                return "⚠️ Response blocked due to sensitive content";
            }
        }
        return response;
    }
}
