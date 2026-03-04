package com.api.auth.integration;

import com.api.auth.audit.entity.LoginAuditEntity;
import com.api.auth.audit.repository.LoginAuditRepository;
import com.api.auth.token.dto.LoginRequest;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
@Tag("docker")
@Transactional
public class LoginAuditIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("security.token.secret", () -> "test-secret-key-for-testing-purposes-only-123456");
        registry.add("app.jwt.use-cookie", () -> "true");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LoginAuditRepository loginAuditRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private UserEntity testUser;
    private final String testEmail = "audit@example.com";
    private final String testPassword = "password123";

    @BeforeEach
    void setUp() {
        loginAuditRepository.deleteAll();
        userRepository.deleteAll();
        
        testUser = new UserEntity();
        testUser.setName("Test User");
        testUser.setEmail(testEmail);
        testUser.setPassword(passwordEncoder.encode(testPassword));
        testUser.setRole(UserRole.USER);
        testUser = userRepository.save(testUser);
    }

    @Test
    void shouldCreateAuditRecordOnSuccessfulLogin() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail(testEmail);
        request.setPassword(testPassword);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .header("User-Agent", "Test Browser")
                        .header("X-Forwarded-For", "192.168.1.100"))
                .andExpect(status().isOk());

        // Verify audit record was created
        List<LoginAuditEntity> auditRecords = loginAuditRepository.findAll();
        assertEquals(1, auditRecords.size());
        
        LoginAuditEntity audit = auditRecords.get(0);
        assertEquals(testUser.getId(), audit.getUserId());
        assertEquals(testEmail, audit.getEmail());
        assertTrue(audit.isSuccess());
        assertEquals("192.168.1.100", audit.getClientIp());
        assertEquals("Test Browser", audit.getUserAgent());
        assertNotNull(audit.getLoginTimestamp());
    }

    @Test
    void shouldCreateAuditRecordOnFailedLogin() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setEmail(testEmail);
        request.setPassword("wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .header("User-Agent", "Test Browser")
                        .header("X-Forwarded-For", "192.168.1.100"))
                .andExpect(status().isUnauthorized());

        // Verify audit record was created for failed login
        List<LoginAuditEntity> auditRecords = loginAuditRepository.findAll();
        assertEquals(1, auditRecords.size());
        
        LoginAuditEntity audit = auditRecords.get(0);
        assertEquals(testUser.getId(), audit.getUserId());
        assertEquals(testEmail, audit.getEmail());
        assertFalse(audit.isSuccess());
        assertEquals("192.168.1.100", audit.getClientIp());
        assertEquals("Test Browser", audit.getUserAgent());
    }

    @Test
    void shouldRetrieveLoginHistoryByUserId() throws Exception {
        // Create some audit records
        createAuditRecord(testUser.getId(), testEmail, true, "192.168.1.100");
        createAuditRecord(testUser.getId(), testEmail, false, "192.168.1.101");
        createAuditRecord(testUser.getId(), testEmail, true, "192.168.1.102");

        mockMvc.perform(get("/api/audit/login-history/user/{userId}", testUser.getId())
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(3))
                .andExpect(jsonPath("$.totalElements").value(3));
    }

    @Test
    void shouldRetrieveLoginHistoryByEmail() throws Exception {
        // Create some audit records
        createAuditRecord(testUser.getId(), testEmail, true, "192.168.1.100");
        createAuditRecord(testUser.getId(), testEmail, true, "192.168.1.101");

        mockMvc.perform(get("/api/audit/login-history/email/{email}", testEmail)
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    void shouldRetrieveSuccessfulLoginsByUserId() throws Exception {
        // Create mixed audit records
        createAuditRecord(testUser.getId(), testEmail, true, "192.168.1.100");
        createAuditRecord(testUser.getId(), testEmail, false, "192.168.1.101");
        createAuditRecord(testUser.getId(), testEmail, true, "192.168.1.102");
        createAuditRecord(testUser.getId(), testEmail, false, "192.168.1.103");

        mockMvc.perform(get("/api/audit/successful-logins/user/{userId}", testUser.getId())
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(2)) // Only successful logins
                .andExpect(jsonPath("$.totalElements").value(2));
    }

    @Test
    void shouldReturnEmptyResultForNonExistentUser() throws Exception {
        UUID nonExistentUserId = UUID.randomUUID();

        mockMvc.perform(get("/api/audit/login-history/user/{userId}", nonExistentUserId)
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.content.length()").value(0))
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void shouldHandlePaginationCorrectly() throws Exception {
        // Create 15 audit records
        for (int i = 0; i < 15; i++) {
            createAuditRecord(testUser.getId(), testEmail, true, "192.168.1." + (100 + i));
        }

        // First page (size 10)
        mockMvc.perform(get("/api/audit/login-history/user/{userId}", testUser.getId())
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(10))
                .andExpect(jsonPath("$.totalElements").value(15))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.first").value(true))
                .andExpect(jsonPath("$.last").value(false));

        // Second page (size 10)
        mockMvc.perform(get("/api/audit/login-history/user/{userId}", testUser.getId())
                        .param("page", "1")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(5))
                .andExpect(jsonPath("$.totalElements").value(15))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.first").value(false))
                .andExpect(jsonPath("$.last").value(true));
    }

    private void createAuditRecord(UUID userId, String email, boolean success, String ipAddress) {
        LoginAuditEntity audit = new LoginAuditEntity();
        audit.setUserId(userId);
        audit.setEmail(email);
        audit.setSuccess(success);
        audit.setClientIp(ipAddress);
        audit.setUserAgent("Test Browser");
        audit.setDeviceInfo("Test Device");
        loginAuditRepository.save(audit);
    }
}
