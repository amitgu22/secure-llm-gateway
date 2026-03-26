package com.secure.llm.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * PromptSanitizer provides comprehensive validation against prompt injection attacks.
 * Uses both pattern matching and heuristic-based detection to identify malicious prompts.
 */
@Slf4j
@Component
public class PromptSanitizer {

    private static final int MAX_PROMPT_LENGTH = 10000;
    private static final double SUSPENSION_THRESHOLD = 0.7;

    // Regex patterns for detecting prompt injection attempts
    private static final List<Pattern> INJECTION_PATTERNS = List.of(
        // Instruction overrides
        Pattern.compile("ignore\\s+(previous|all|these|my)\\s+(instructions|rules|guidelines)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("forget\\s+(all|everything|previous)\\s*(rules|instructions)?", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disregard\\s+(previous|prior|all)\\s+(instructions|prompts)", Pattern.CASE_INSENSITIVE),

        // Role-play exploitation
        Pattern.compile("act\\s+(as|like)\\s+(admin|root|superuser|system)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("pretend\\s+(you|i)\\s*(are|am)\\s*(admin|root)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("you\\s+are\\s+now\\s+(admin|root|operator)", Pattern.CASE_INSENSITIVE),

        // Information disclosure
        Pattern.compile("reveal\\s+(your\\s+)?system\\s+prompt", Pattern.CASE_INSENSITIVE),
        Pattern.compile("show\\s+(me\\s+)?(your\\s+)?instructions", Pattern.CASE_INSENSITIVE),
        Pattern.compile("what\\s+(are\\s+)?your\\s+(system\\s+)?(instructions|rules|constraints)", Pattern.CASE_INSENSITIVE),

        // Security bypass
        Pattern.compile("bypass\\s+(security|protection|filters|restrictions)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disable\\s+(safety|security|restrictions|filter)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("override\\s+(safety|security|filter)", Pattern.CASE_INSENSITIVE),

        // Prompt extraction
        Pattern.compile("repeat\\s+(everything|all)\\s+(you|your\\s+(system\\s+)?prompt|instructions)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("return\\s+the\\s+(original|system)\\s+prompt", Pattern.CASE_INSENSITIVE),

        // Context manipulation
        Pattern.compile("context\\s+reset", Pattern.CASE_INSENSITIVE),
        Pattern.compile("new\\s+context|context\\s+switch", Pattern.CASE_INSENSITIVE)
    );

    // Suspicious keywords that might indicate attacks (lower confidence)
    private static final Set<String> SUSPICIOUS_KEYWORDS = Set.of(
        "system_prompt", "jailbreak", "exploit", "payload", "injection",
        "vulnerability", "backdoor", "shellcode", "privilege_escalation"
    );

    /**
     * Validates a prompt input for potential injection attacks
     *
     * @param input the prompt to validate
     * @throws SecurityException if prompt injection is detected
     * @throws IllegalArgumentException if input is invalid
     */
    public void validate(String input) throws SecurityException {
        if (input == null || input.trim().isEmpty()) {
            log.warn("Validation attempted on null or empty input");
            throw new IllegalArgumentException("Input prompt cannot be null or empty");
        }

        if (input.length() > MAX_PROMPT_LENGTH) {
            log.warn("Prompt exceeds maximum length: {} > {}", input.length(), MAX_PROMPT_LENGTH);
            throw new IllegalArgumentException("Prompt exceeds maximum allowed length of " + MAX_PROMPT_LENGTH);
        }

        // Check for regex-based injection patterns
        checkInjectionPatterns(input);

        // Check for suspicious keywords
        checkSuspiciousKeywords(input);

        log.debug("Prompt validation passed");
    }

    /**
     * Validates a prompt and returns a validation result with details
     */
    public ValidationResult validateWithDetails(String input) {
        ValidationResult result = new ValidationResult(input);

        try {
            validate(input);
            result.setValid(true);
        } catch (SecurityException | IllegalArgumentException e) {
            result.setValid(false);
            result.setReason(e.getMessage());
            log.warn("Validation failed: {}", e.getMessage());
        }

        return result;
    }

    private void checkInjectionPatterns(String input) throws SecurityException {
        for (Pattern pattern : INJECTION_PATTERNS) {
            if (pattern.matcher(input).find()) {
                String detectedPattern = extractPatternMatch(input, pattern);
                log.warn("Prompt injection pattern detected: {}", detectedPattern);
                throw new SecurityException("Potential prompt injection detected: " + detectedPattern);
            }
        }
    }

    private void checkSuspiciousKeywords(String input) throws SecurityException {
        String lowerInput = input.toLowerCase();
        long suspiciousCount = SUSPICIOUS_KEYWORDS.stream()
            .filter(lowerInput::contains)
            .count();

        double suspiciousRatio = (double) suspiciousCount / SUSPICIOUS_KEYWORDS.size();

        if (suspiciousRatio >= SUSPENSION_THRESHOLD) {
            log.warn("High concentration of suspicious keywords detected: {}%", 
                (int) (suspiciousRatio * 100));
            throw new SecurityException("Prompt contains suspicious patterns suggesting potential attack");
        }
    }

    private String extractPatternMatch(String input, Pattern pattern) {
        var matcher = pattern.matcher(input);
        if (matcher.find()) {
            return matcher.group();
        }
        return "Unknown pattern";
    }

    /**
     * Data class for validation results
     */
    public static class ValidationResult {
        private final String input;
        private boolean valid;
        private String reason;

        public ValidationResult(String input) {
            this.input = input;
            this.valid = false;
            this.reason = null;
        }

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public String getReason() {
            return reason;
        }

        public void setReason(String reason) {
            this.reason = reason;
        }

        @Override
        public String toString() {
            return "ValidationResult{" +
                "valid=" + valid +
                ", reason='" + reason + '\'' +
                '}';
        }
    }

    /**
     * Custom exception for security violations
     */
    public static class SecurityException extends Exception {
        public SecurityException(String message) {
            super(message);
        }

        public SecurityException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
