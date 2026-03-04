package com.api.auth.integration;

import com.api.auth.token.dto.LoginRequest;

import com.api.auth.token.entity.RefreshTokenEntity;
import com.api.auth.token.repository.RefreshTokenRepository;
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
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import jakarta.servlet.http.Cookie;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers(disabledWithoutDocker = true)
@Tag("docker")
@Transactional
class AuthIntegrationTest {

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
        registry.add("app.jwt.access-expiration", () -> "900");
        registry.add("app.jwt.refresh-expiration", () -> "604800");
        registry.add("app.security.same-site", () -> "Lax");
        registry.add("app.security.secure-cookie", () -> "false");
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
        testUser.setId(UUID.randomUUID());
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
    void completeAuthFlow_ShouldWorkCorrectly() throws Exception {
        // 1. Login - deve retornar access token e refresh token via cookie
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(jsonPath("$.expiresIn").value(900)) // 15 minutos
                .andExpect(jsonPath("$.refreshExpiresIn").value(604800)) // 7 dias
                .andExpect(header().exists("Set-Cookie"))
                .andReturn();

        String refreshToken = extractRefreshTokenFromSetCookie(loginResult.getResponse().getHeader("Set-Cookie"));
        assertNotNull(refreshToken);

        // Verifica se o refresh token foi salvo no banco
        assertEquals(1, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        // 2. Refresh - deve gerar novos tokens
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.refreshExpiresIn").value(604800))
                .andExpect(header().exists("Set-Cookie"))
                .andReturn();

        String newRefreshToken = extractRefreshTokenFromSetCookie(refreshResult.getResponse().getHeader("Set-Cookie"));
        assertNotNull(newRefreshToken);
        assertNotEquals(refreshToken, newRefreshToken); // Token deve ter rotacionado

        // Ainda deve haver apenas 1 token ativo (rotação)
        assertEquals(1, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        // 3. Tentativa de usar o token antigo - deve falhar
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isUnauthorized());

        // 4. Logout - deve revogar o token atual
        mockMvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("refresh_token", newRefreshToken)))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        // Não deve haver tokens ativos
        assertEquals(0, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        // 5. Tentativa de refresh após logout - deve falhar
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", newRefreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_WithInvalidCredentials_ShouldReturnUnauthorized() throws Exception {
        LoginRequest invalidRequest = new LoginRequest();
        invalidRequest.setEmail("test@example.com");
        invalidRequest.setPassword("wrongpassword");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_WithInvalidToken_ShouldReturnUnauthorized() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", "invalid-token")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAll_ShouldRevokeAllUserTokens() throws Exception {
        // Login para criar token
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String refreshToken = extractRefreshTokenFromSetCookie(loginResult.getResponse().getHeader("Set-Cookie"));
        assertNotNull(refreshToken);

        // Simula múltiplos tokens (criando manualmente)
        RefreshTokenEntity additionalToken = new RefreshTokenEntity();
        additionalToken.setUserId(testUser.getId());
        additionalToken.setTokenHash("additional-hash");
        additionalToken.setDeviceInfo("Another Device");
        additionalToken.setExpiresAt(Instant.now().plusSeconds(3600)); // 1 hora de validade
        refreshTokenRepository.save(additionalToken);

        assertEquals(2, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        // Logout all
        mockMvc.perform(post("/api/auth/logout-all")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        // Todos os tokens devem estar revogados
        assertEquals(0, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));
    }

    @Test
    void tokenReuse_ShouldRevokeAllUserTokens() throws Exception {
        // Login inicial
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String originalRefreshToken = extractRefreshTokenFromSetCookie(loginResult.getResponse().getHeader("Set-Cookie"));
        assertNotNull(originalRefreshToken);

        // Primeiro refresh (válido)
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", originalRefreshToken)))
                .andExpect(status().isOk());

        // Tentativa de reutilizar o token já usado (deve detectar reuso)
        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", originalRefreshToken)))
                .andExpect(status().isUnauthorized());

        // Todos os tokens do usuário devem estar revogados
        assertEquals(0, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));
    }

    private String extractRefreshTokenFromSetCookie(String setCookieHeader) {
        assertNotNull(setCookieHeader);
        int start = setCookieHeader.indexOf("refresh_token=");
        assertTrue(start >= 0);
        int valueStart = start + "refresh_token=".length();
        int end = setCookieHeader.indexOf(";", valueStart);
        assertTrue(end > valueStart);
        return setCookieHeader.substring(valueStart, end);
    }
}
