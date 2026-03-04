package com.api.auth.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import com.api.auth.providers.JWTProvider;
import com.api.auth.security.jwtkeys.JwtKeyRing;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

class JwtKeyRotationTest {

    private static final String KEY1 = "test-secret-key-1-should-be-at-least-32-chars";
    private static final String KEY2 = "test-secret-key-2-should-be-at-least-32-chars";

    @Test
    void tokenSignedWithKey1_ShouldValidate_AndKidShouldBeKey1() {
        JwtKeyRing ring = new JwtKeyRing("key1", Map.of("key1", KEY1, "key2", KEY2));
        JWTProvider provider = new JWTProvider(ring);
        ReflectionTestUtils.setField(provider, "accessTokenExpirationSeconds", 900L);

        UserEntity user = new UserEntity();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setRole(UserRole.USER);

        String token = provider.generateAccessToken(user);

        assertEquals("key1", JWT.decode(token).getKeyId());
        assertEquals(user.getId().toString(), provider.validateToken("Bearer " + token));
    }

    @Test
    void switchActiveKidToKey2_NewTokensUseKidKey2_OldTokensStillValidate() {
        JwtKeyRing ringKey1Active = new JwtKeyRing("key1", Map.of("key1", KEY1, "key2", KEY2));
        JWTProvider providerKey1 = new JWTProvider(ringKey1Active);
        ReflectionTestUtils.setField(providerKey1, "accessTokenExpirationSeconds", 900L);

        UserEntity user = new UserEntity();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setRole(UserRole.USER);

        String tokenKey1 = providerKey1.generateAccessToken(user);
        assertEquals("key1", JWT.decode(tokenKey1).getKeyId());

        JwtKeyRing ringKey2Active = new JwtKeyRing("key2", Map.of("key1", KEY1, "key2", KEY2));
        JWTProvider providerKey2 = new JWTProvider(ringKey2Active);
        ReflectionTestUtils.setField(providerKey2, "accessTokenExpirationSeconds", 900L);

        String tokenKey2 = providerKey2.generateAccessToken(user);
        assertEquals("key2", JWT.decode(tokenKey2).getKeyId());

        assertEquals(user.getId().toString(), providerKey2.validateToken("Bearer " + tokenKey1));
    }

    @Test
    void tokenWithoutKid_ShouldStillValidate() {
        JwtKeyRing ringKey2Active = new JwtKeyRing("key2", Map.of("key1", KEY1, "key2", KEY2));
        JWTProvider provider = new JWTProvider(ringKey2Active);
        ReflectionTestUtils.setField(provider, "accessTokenExpirationSeconds", 900L);

        UUID userId = UUID.randomUUID();
        Algorithm algorithmKey1 = Algorithm.HMAC256(KEY1);

        String tokenWithoutKid = JWT.create()
                .withIssuer("auth-api")
                .withSubject(userId.toString())
                .withClaim("email", "user@example.com")
                .withClaim("role", "USER")
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(algorithmKey1);

        String subject = provider.validateToken("Bearer " + tokenWithoutKid);
        assertNotNull(subject);
        assertEquals(userId.toString(), subject);
    }
}
