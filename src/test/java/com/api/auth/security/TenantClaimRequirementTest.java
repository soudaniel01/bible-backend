package com.api.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.api.auth.providers.JWTProvider;
import com.api.auth.security.jwtkeys.JwtKeyRing;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

class TenantClaimRequirementTest {

    private JWTProvider jwtProvider;

    private final String secret = "test-secret-key-for-testing-purposes-only";
    private final String issuer = "auth-api";
    private final UUID userId = UUID.randomUUID();
    private final String email = "test@example.com";
    private final String role = "USER";
    private final String tenantId = "550e8400-e29b-41d4-a716-446655440000";

    @BeforeEach
    void setUp() {
        JwtKeyRing keyRing = new JwtKeyRing("key1", java.util.Map.of("key1", secret));
        jwtProvider = new JWTProvider(keyRing);
        ReflectionTestUtils.setField(jwtProvider, "accessTokenExpirationSeconds", 900L);
    }

    @Test
    void whenFlagFalse_tokenWithoutTenantIdIsAccepted() {
        ReflectionTestUtils.setField(jwtProvider, "requireTenantClaim", false);
        String token = bearer(createToken(false));

        String subject = jwtProvider.validateToken(token);
        assertEquals(userId.toString(), subject);

        var user = jwtProvider.validateTokenAndExtractUser(token);
        assertNotNull(user);
        assertEquals(userId.toString(), user.getId());
        assertEquals(email, user.getEmail());
        assertEquals(role, user.getRole());
    }

    @Test
    void whenFlagTrue_tokenWithoutTenantIdIsRejected() {
        ReflectionTestUtils.setField(jwtProvider, "requireTenantClaim", true);
        String token = bearer(createToken(false));

        assertTrue(jwtProvider.validateToken(token).isEmpty());
        assertNull(jwtProvider.validateTokenAndExtractUser(token));
    }

    @Test
    void tokenWithTenantIdIsAcceptedWithFlagOnOrOff() {
        String token = bearer(createToken(true));

        ReflectionTestUtils.setField(jwtProvider, "requireTenantClaim", false);
        assertEquals(userId.toString(), jwtProvider.validateToken(token));
        assertNotNull(jwtProvider.validateTokenAndExtractUser(token));

        ReflectionTestUtils.setField(jwtProvider, "requireTenantClaim", true);
        assertEquals(userId.toString(), jwtProvider.validateToken(token));
        assertNotNull(jwtProvider.validateTokenAndExtractUser(token));
    }

    private String bearer(String jwt) {
        return "Bearer " + jwt;
    }

    private String createToken(boolean includeTenantId) {
        Algorithm algorithm = Algorithm.HMAC256(secret);

        var builder = JWT.create()
                .withIssuer(issuer)
                .withSubject(userId.toString())
                .withClaim("email", email)
                .withClaim("role", role)
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)));

        if (includeTenantId) {
            builder.withClaim("tenantId", tenantId);
        }

        return builder.sign(algorithm);
    }
}

