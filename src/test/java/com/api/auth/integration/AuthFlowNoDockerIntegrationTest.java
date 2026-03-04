package com.api.auth.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import com.api.auth.token.dto.LoginRequest;
import com.api.auth.token.entity.RefreshTokenEntity;
import com.api.auth.token.repository.RefreshTokenRepository;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test-h2")
@Transactional
class AuthFlowNoDockerIntegrationTest {

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
        testEmail = "test_" + System.currentTimeMillis() + "@example.com";

        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        testUser = new UserEntity();
        testUser.setId(UUID.randomUUID());
        testUser.setName("Test User");
        testUser.setEmail(testEmail);
        testUser.setPassword(passwordEncoder.encode("password123"));
        testUser.setRole(UserRole.USER);
        testUser = userRepository.save(testUser);

        loginRequest = new LoginRequest();
        loginRequest.setEmail(testEmail);
        loginRequest.setPassword("password123");
    }

    @Test
    void authFlow_LoginRefreshLogoutLogoutAll_ShouldWork() throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(header().exists("Set-Cookie"))
                .andReturn();

        String refreshToken = extractRefreshTokenFromSetCookie(loginResult.getResponse().getHeader("Set-Cookie"));
        assertNotNull(refreshToken);
        assertEquals(1, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andExpect(header().exists("Set-Cookie"))
                .andReturn();

        String newRefreshToken = extractRefreshTokenFromSetCookie(refreshResult.getResponse().getHeader("Set-Cookie"));
        assertNotNull(newRefreshToken);
        assertNotEquals(refreshToken, newRefreshToken);
        assertEquals(1, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        mockMvc.perform(post("/api/auth/refresh")
                        .cookie(new Cookie("refresh_token", refreshToken)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/logout")
                        .cookie(new Cookie("refresh_token", newRefreshToken)))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        assertEquals(0, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        MvcResult loginResult2 = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"))
                .andReturn();

        String refreshToken2 = extractRefreshTokenFromSetCookie(loginResult2.getResponse().getHeader("Set-Cookie"));
        assertNotNull(refreshToken2);

        RefreshTokenEntity additionalToken = new RefreshTokenEntity();
        additionalToken.setUserId(testUser.getId());
        additionalToken.setTokenHash("additional-hash");
        additionalToken.setDeviceInfo("Another Device");
        additionalToken.setExpiresAt(Instant.now().plusSeconds(3600));
        refreshTokenRepository.save(additionalToken);

        assertEquals(2, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));

        mockMvc.perform(post("/api/auth/logout-all")
                        .cookie(new Cookie("refresh_token", refreshToken2)))
                .andExpect(status().isOk())
                .andExpect(header().exists("Set-Cookie"));

        assertEquals(0, refreshTokenRepository.countActiveTokensByUserId(testUser.getId(), Instant.now()));
    }

    private String extractRefreshTokenFromSetCookie(String setCookieHeader) {
        int start = setCookieHeader.indexOf("refresh_token=");
        int valueStart = start + "refresh_token=".length();
        int end = setCookieHeader.indexOf(";", valueStart);
        return setCookieHeader.substring(valueStart, end);
    }
}

