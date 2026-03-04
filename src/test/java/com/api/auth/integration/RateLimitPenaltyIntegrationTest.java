package com.api.auth.integration;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
        "app.security.ratelimit.login.ip.capacity=1000",
        "app.security.ratelimit.login.ip.windowSeconds=60",
        "app.security.ratelimit.login.principal.capacity=1000",
        "app.security.ratelimit.login.principal.windowSeconds=60",
        "app.security.ratelimit.penalty.enabled=true",
        "app.security.ratelimit.penalty.cooldownSeconds=1"
})
@AutoConfigureMockMvc
@ActiveProfiles("test-h2")
@Transactional
class RateLimitPenaltyIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private String email;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        email = "penalty_" + System.currentTimeMillis() + "@example.com";

        UserEntity user = new UserEntity();
        user.setId(UUID.randomUUID());
        user.setName("Penalty User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole(UserRole.USER);
        userRepository.save(user);
    }

    @Test
    void penalty_failedLogin_ShouldCooldownByPrincipal() throws Exception {
        LoginRequest wrongPassword = new LoginRequest();
        wrongPassword.setEmail(email);
        wrongPassword.setPassword("wrong");

        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "5.6.7.8")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(wrongPassword))
                        .with(request -> {
                            request.setRemoteAddr("5.6.7.8");
                            return request;
                        }))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "5.6.7.8")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(wrongPassword))
                        .with(request -> {
                            request.setRemoteAddr("5.6.7.8");
                            return request;
                        }))
                .andExpect(status().isTooManyRequests())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(content().json("{\"error\":\"RATE_LIMITED\",\"message\":\"Too many requests\"}", true));

        Thread.sleep(1100);

        mockMvc.perform(post("/api/auth/login")
                        .header("X-Forwarded-For", "5.6.7.8")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(wrongPassword))
                        .with(request -> {
                            request.setRemoteAddr("5.6.7.8");
                            return request;
                        }))
                .andExpect(status().isUnauthorized());
    }
}
