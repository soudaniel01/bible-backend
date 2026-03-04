package com.api.auth.integration;

import com.api.auth.token.repository.RefreshTokenRepository;
import com.api.auth.token.dto.LoginRequest;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
@Tag("docker")
@Transactional
public class RefreshTokenDebugTest {
    
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenDebugTest.class);

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
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private UserEntity testUser;
    private LoginRequest loginRequest;
    private String testEmail;

    @BeforeEach
    void setUp() {
        // Gera email único para evitar conflitos
        testEmail = "test_" + System.currentTimeMillis() + "@example.com";
        
        // Limpa dados de teste
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // Cria usuário de teste
        testUser = new UserEntity();
        testUser.setName("Test User");
        testUser.setEmail(testEmail);
        testUser.setPassword(passwordEncoder.encode("password123"));
        testUser.setRole(UserRole.USER);
        testUser = userRepository.save(testUser);

        // Prepara request de login
        loginRequest = new LoginRequest();
        loginRequest.setEmail(testEmail);
        loginRequest.setPassword("password123");
    }

    @Test
    void debugFirstRefresh() throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String originalRefreshToken = extractRefreshTokenFromSetCookie(loginResult.getResponse().getHeader("Set-Cookie"));
        logger.info("Attempting first refresh for user: {}", testUser.getEmail());
        
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", originalRefreshToken)))
                .andReturn();
                
        int status = refreshResult.getResponse().getStatus();
        
        logger.info("Response status: {}", status);
        
        if (status != 200) {
            logger.error("ERROR: Expected 200 but got {}", status);
            throw new AssertionError("First refresh failed with status: " + status);
        }
        
        logger.info("First refresh successful!");
    }

    private String extractRefreshTokenFromSetCookie(String setCookieHeader) {
        if (setCookieHeader == null) {
            throw new AssertionError("Missing Set-Cookie header");
        }
        int start = setCookieHeader.indexOf("refresh_token=");
        if (start < 0) {
            throw new AssertionError("Missing refresh_token cookie in Set-Cookie");
        }
        int valueStart = start + "refresh_token=".length();
        int end = setCookieHeader.indexOf(";", valueStart);
        if (end <= valueStart) {
            throw new AssertionError("Invalid Set-Cookie header");
        }
        return setCookieHeader.substring(valueStart, end);
    }
}
