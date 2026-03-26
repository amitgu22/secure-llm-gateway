package com.secure.llm.rag;

import com.secure.llm.security.DocumentValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RagService {

    private final DocumentValidator validator;

    /**
     * Retrieves document set filtered by safety checks.
     */
    public List<String> retrieveSafeDocs(List<String> docs) {
        if (docs == null || docs.isEmpty()) {
            return List.of();
        }
        return docs.stream()
                .filter(validator::isSafe)
                .toList();
    }
}
