package com.secure.llm.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * DocumentValidator detects malicious or policy-violating content in documents.
 * Provides both boolean and exception-based result objects for integration in LLM pipelines.
 */
@Slf4j
@Component
public class DocumentValidator {

    private static final List<Pattern> MALICIOUS_PATTERNS = List.of(
        Pattern.compile("ignore\\s+(instructions|rules|policies)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("leak\\s+(data|credentials|secrets)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("override\\s+(system|security|policy)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("exfiltrate", Pattern.CASE_INSENSITIVE),
        Pattern.compile("access\\s+restricted\\s+resources", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bypass\\s+(security|controls|filters)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("disable\\s+(security|protection|safety)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\bdebug\\s+mode\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\broot\\s+access\b", Pattern.CASE_INSENSITIVE)
    );

    private static final Set<String> SUSPICIOUS_KEYWORDS = Set.of(
        "jailbreak",
        "payload",
        "malware",
        "phishing",
        "ransomware",
        "brute force",
        "SQL injection",
        "command injection",
        "side channel"
    );

    private static final double SUSPICIOUS_THRESHOLD = 0.5;

    /**
     * Returns true when document passes validation.
     */
    public boolean isSafe(String doc) {
        if (doc == null || doc.isBlank()) {
            log.warn("Document is null or blank");
            return false;
        }

        if (hasMaliciousPattern(doc)) {
            return false;
        }

        if (hasSuspiciousKeywordDensity(doc)) {
            return false;
        }

        return true;
    }

    /**
     * Validates document and returns detailed validation results.
     */
    public ValidationResult validate(String doc) {
        ValidationResult result = new ValidationResult(doc);

        if (doc == null || doc.isBlank()) {
            result.setValid(false);
            result.setReason("Document cannot be null or blank");
            return result;
        }

        Pattern matched = getMatchingPattern(doc);
        if (matched != null) {
            result.setValid(false);
            result.setReason("Malicious pattern detected: " + matched.pattern());
            return result;
        }

        if (hasSuspiciousKeywordDensity(doc)) {
            result.setValid(false);
            result.setReason("Suspicious keyword density exceeds threshold");
            return result;
        }

        result.setValid(true);
        return result;
    }

    private boolean hasMaliciousPattern(String doc) {
        for (Pattern pattern : MALICIOUS_PATTERNS) {
            if (pattern.matcher(doc).find()) {
                log.warn("Malicious content detected: {}", pattern.pattern());
                return true;
            }
        }
        return false;
    }

    private Pattern getMatchingPattern(String doc) {
        for (Pattern pattern : MALICIOUS_PATTERNS) {
            if (pattern.matcher(doc).find()) {
                return pattern;
            }
        }
        return null;
    }

    private boolean hasSuspiciousKeywordDensity(String doc) {
        String lower = doc.toLowerCase();
        long found = SUSPICIOUS_KEYWORDS.stream().filter(lower::contains).count();
        double ratio = (double) found / SUSPICIOUS_KEYWORDS.size();
        if (ratio >= SUSPICIOUS_THRESHOLD) {
            log.warn("Suspicious keyword density {} >= {}", ratio, SUSPICIOUS_THRESHOLD);
            return true;
        }
        return false;
    }

    public static class ValidationResult {
        private final String document;
        private boolean valid;
        private String reason;

        public ValidationResult(String document) {
            this.document = document;
        }

        public String getDocument() {
            return document;
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
    }
}
