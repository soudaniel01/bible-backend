package com.api.auth.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import org.springframework.transaction.annotation.Transactional;

import com.api.auth.token.dto.LoginRequest;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest(properties = {
        "app.login.suspension.ip.max-attempts=10000",
        "app.login.suspension.email.max-attempts=10000",
        "app.security.ratelimit.enabled=true",
        "app.security.ratelimit.login.ip.capacity=2",
        "app.security.ratelimit.login.ip.windowSeconds=1",
        "app.security.ratelimit.login.principal.capacity=2",
        "app.security.ratelimit.login.principal.windowSeconds=1",
        "app.security.ratelimit.penalty.enabled=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("test-h2")
@Transactional
class RateLimitIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        String testEmail = "rate_" + System.currentTimeMillis() + "@example.com";

        UserEntity user = new UserEntity();
        user.setId(UUID.randomUUID());
        user.setName("Rate User");
        user.setEmail(testEmail);
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole(UserRole.USER);
        userRepository.save(user);

        loginRequest = new LoginRequest();
        loginRequest.setEmail(testEmail);
        loginRequest.setPassword("password123");
    }

    @Test
    void rateLimit_loginAboveLimit_ShouldReturn429_AndResetAfterWindow() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "1.2.3.4")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(request -> {
                            request.setRemoteAddr("1.2.3.4");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "1.2.3.4")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(request -> {
                            request.setRemoteAddr("1.2.3.4");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "1.2.3.4")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(request -> {
                            request.setRemoteAddr("1.2.3.4");
                            return request;
                        }))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(content().json("{\"error\":\"RATE_LIMITED\",\"message\":\"Too many requests\"}", true));

        Thread.sleep(1100);

        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "1.2.3.4")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest))
                        .with(request -> {
                            request.setRemoteAddr("1.2.3.4");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }

    
}
