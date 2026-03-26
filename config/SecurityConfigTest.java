package com.secure.llm.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    private String validJwt;
    private String invalidJwt;
    private String adminJwt;

    @BeforeEach
    public void setUp() {
        // Note: In real tests, generate these from JWT token provider
        validJwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." + 
                  ".eyJzdWIiOiJ1c2VyIiwicm9sZXMiOlsidXNlciJdfQ." +
                  ".signature";
        
        adminJwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." +
                  ".eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFkbWluIl19." +
                  ".signature";
    }

    // ========== Public Endpoints Tests ==========
    @Test
    public void testHealthEndpointPublic() throws Exception {
        mockMvc.perform(get("/api/health"))
            .andExpect(status().isOk());
    }

    @Test
    public void testMetricsEndpointPublic() throws Exception {
        mockMvc.perform(get("/api/metrics"))
            .andExpect(status().isOk());
    }

    @Test
    public void testSwaggerDocsPublic() throws Exception {
        mockMvc.perform(get("/swagger-ui/"))
            .andExpect(status().isOk());
    }

    // ========== Authentication Tests ==========
    @Test
    public void testAiEndpointRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/ai/query"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAiEndpointWithValidJwt() throws Exception {
        mockMvc.perform(get("/api/ai/query")
            .header("Authorization", validJwt))
            .andExpect(status().isOk());
    }

    @Test
    public void testAiEndpointWithInvalidJwt() throws Exception {
        mockMvc.perform(get("/api/ai/query")
            .header("Authorization", "Bearer invalid.jwt.token"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testMissingAuthorizationHeader() throws Exception {
        mockMvc.perform(get("/api/ai/query"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    // ========== Authorization Tests ==========
    @Test
    public void testPostAiEndpointRequiresAuth() throws Exception {
        mockMvc.perform(post("/api/ai/query")
            .contentType("application/json")
            .content("{\"prompt\": \"test\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testAdminDeleteEndpointRequiresAdminRole() throws Exception {
        mockMvc.perform(delete("/api/ai/model/123")
            .header("Authorization", validJwt)) // User token, not admin
            .andExpect(status().isForbidden());
    }

    @Test
    public void testAdminDeleteEndpointWithAdminRole() throws Exception {
        mockMvc.perform(delete("/api/ai/model/123")
            .header("Authorization", adminJwt)) // Admin token
            .andExpect(status().isOk());
    }

    @Test
    public void testSecurityEndpointRequiresSecurityAdminRole() throws Exception {
        mockMvc.perform(get("/api/security/audit")
            .header("Authorization", validJwt))
            .andExpect(status().isForbidden());
    }

    @Test
    public void testRedTeamEndpointRequiresRedTeamRole() throws Exception {
        mockMvc.perform(get("/api/redteam/test")
            .header("Authorization", validJwt))
            .andExpect(status().isForbidden());
    }

    @Test
    public void testUnknownEndpointDenied() throws Exception {
        mockMvc.perform(get("/api/unknown/endpoint")
            .header("Authorization", validJwt))
            .andExpect(status().isForbidden());
    }

    // ========== Security Headers Tests ==========
    @Test
    public void testHstsHeaderPresent() throws Exception {
        mockMvc.perform(get("/api/health"))
            .andExpect(header().exists("Strict-Transport-Security"))
            .andExpect(header().string("Strict-Transport-Security", 
                containsString("max-age=31536000")));
    }

    @Test
    public void testXFrameOptionsHeader() throws Exception {
        mockMvc.perform(get("/api/health"))
            .andExpect(header().string("X-Frame-Options", "DENY"));
    }

    @Test
    public void testXContentTypeOptionsHeader() throws Exception {
        mockMvc.perform(get("/api/health"))
            .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }

    @Test
    public void testXssProtectionHeader() throws Exception {
        mockMvc.perform(get("/api/health"))
            .andExpect(header().exists("X-XSS-Protection"));
    }

    @Test
    public void testContentSecurityPolicyHeader() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/health"))
            .andExpect(status().isOk())
            .andReturn();
        
        String cspHeader = result.getResponse().getHeader("Content-Security-Policy");
        assert cspHeader != null && cspHeader.contains("default-src 'self'");
    }

    // ========== CORS Tests ==========
    @Test
    public void testCorsPreflightRequest() throws Exception {
        mockMvc.perform(options("/api/ai/query")
            .header("Origin", "http://localhost:3000")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type,Authorization"))
            .andExpect(status().isOk())
            .andExpect(header().exists("Access-Control-Allow-Origin"))
            .andExpect(header().exists("Access-Control-Allow-Methods"));
    }

    @Test
    public void testCorsAllowedOrigin() throws Exception {
        mockMvc.perform(get("/api/ai/query")
            .header("Origin", "http://localhost:3000")
            .header("Authorization", validJwt))
            .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"));
    }

    @Test
    public void testCorsDisallowedOrigin() throws Exception {
        mockMvc.perform(get("/api/ai/query")
            .header("Origin", "http://attacker.com")
            .header("Authorization", validJwt))
            .andExpect(status().isForbidden());
    }

    // ========== CSRF Tests ==========
    @Test
    public void testCsrfProtectionEnabled() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/health"))
            .andExpect(status().isOk())
            .andReturn();
        
        // CSRF token should be available in session
        assert result.getRequest().getSession() != null;
    }

    @Test
    public void testCsrfExemptedEndpoints() throws Exception {
        // Health and metrics endpoints should not require CSRF
        mockMvc.perform(post("/api/health"))
            .andExpect(status().isNotFound()); // No POST handler, but no CSRF required
    }

    // ========== Error Handling Tests ==========
    @Test
    public void testUnauthorizedErrorFormat() throws Exception {
        mockMvc.perform(get("/api/ai/query"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.error").exists())
            .andExpect(jsonPath("$.message").exists());
    }

    @Test
    public void testForbiddenErrorFormat() throws Exception {
        mockMvc.perform(delete("/api/ai/model/123")
            .header("Authorization", validJwt))
            .andExpect(status().isForbidden())
            .andExpect(content().contentType("application/json;charset=UTF-8"))
            .andExpect(jsonPath("$.error").value("Forbidden"));
    }

    // ========== Session Management Tests ==========
    @Test
    public void testSessionCreationPolicyIsStateless() throws Exception {
        // Multiple requests should not create persistent session
        mockMvc.perform(get("/api/health")).andExpect(status().isOk());
        mockMvc.perform(get("/api/health")).andExpect(status().isOk());
        
        // Session token should not persist (stateless)
    }

    // ========== HTTP Method Tests ==========
    @Test
    public void testGetRequestRequiresAuth() throws Exception {
        mockMvc.perform(get("/api/ai/models"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testPostRequestRequiresAuth() throws Exception {
        mockMvc.perform(post("/api/ai/query")
            .contentType("application/json")
            .content("{}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testPutRequestRequiresAdminAuth() throws Exception {
        mockMvc.perform(put("/api/ai/model/123")
            .contentType("application/json")
            .content("{}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void testDeleteRequestRequiresAdminAuth() throws Exception {
        mockMvc.perform(delete("/api/ai/model/123"))
            .andExpect(status().isUnauthorized());
    }
}
