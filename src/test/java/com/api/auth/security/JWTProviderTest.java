package com.api.auth.security;

import com.api.auth.providers.JWTProvider;
import com.api.auth.security.jwtkeys.JwtKeyRing;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Testes para JWTProvider focando em cenários de segurança:
 * - Issuer incorreto
 * - Token expirado
 * - Assinatura inválida
 * - Estrutura malformada
 */
@ExtendWith(MockitoExtension.class)
class JWTProviderTest {

    private JWTProvider jwtProvider;
    private final String validSecret = "test-secret-key-for-testing-purposes-only";
    private final String invalidSecret = "wrong-secret-key";
    private final String validIssuer = "auth-api";
    private final String invalidIssuer = "malicious-issuer";
    private final UUID testUserId = UUID.randomUUID();
    private final String testEmail = "test@example.com";
    private final String testRole = "USER";

    @BeforeEach
    void setUp() {
        JwtKeyRing keyRing = new JwtKeyRing("key1", Map.of("key1", validSecret));
        jwtProvider = new JWTProvider(keyRing);
        ReflectionTestUtils.setField(jwtProvider, "accessTokenExpirationSeconds", 900L);
    }

    @Test
    void validateToken_WithValidToken_ShouldReturnUserId() {
        // Given - Criar token válido manualmente
        Algorithm algorithm = Algorithm.HMAC256(validSecret);
        String validToken = JWT.create()
                .withIssuer(validIssuer)
                .withSubject(testUserId.toString())
                .withClaim("email", testEmail)
                .withClaim("role", testRole)
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(algorithm);
        
        String tokenWithBearer = "Bearer " + validToken;
        
        // When & Then
        String result = jwtProvider.validateToken(tokenWithBearer);
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals(testUserId.toString(), result);
    }

    @Test
    void validateToken_WithWrongIssuer_ShouldReturnEmpty() {
        // Given - Criar token com issuer incorreto
        Algorithm algorithm = Algorithm.HMAC256(validSecret);
        String tokenWithWrongIssuer = JWT.create()
                .withIssuer(invalidIssuer) // Issuer incorreto
                .withSubject(testUserId.toString())
                .withClaim("email", testEmail)
                .withClaim("role", testRole)
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(algorithm);

        String tokenWithBearer = "Bearer " + tokenWithWrongIssuer;

        // When & Then
        String result = jwtProvider.validateToken(tokenWithBearer);
        assertTrue(result.isEmpty());
    }

    @Test
    void validateToken_WithExpiredToken_ShouldReturnEmpty() {
        // Given - Criar token já expirado
        Algorithm algorithm = Algorithm.HMAC256(validSecret);
        String expiredToken = JWT.create()
                .withIssuer(validIssuer)
                .withSubject(testUserId.toString())
                .withClaim("email", testEmail)
                .withClaim("role", testRole)
                .withExpiresAt(Date.from(Instant.now().minus(1, ChronoUnit.HOURS))) // Expirado há 1 hora
                .sign(algorithm);

        String tokenWithBearer = "Bearer " + expiredToken;

        // When & Then
        String result = jwtProvider.validateToken(tokenWithBearer);
        assertTrue(result.isEmpty());
    }

    @Test
    void validateToken_WithInvalidSignature_ShouldReturnEmpty() {
        // Given - Criar token com assinatura inválida (secret diferente)
        Algorithm wrongAlgorithm = Algorithm.HMAC256(invalidSecret);
        String tokenWithInvalidSignature = JWT.create()
                .withIssuer(validIssuer)
                .withSubject(testUserId.toString())
                .withClaim("email", testEmail)
                .withClaim("role", testRole)
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(wrongAlgorithm); // Assinatura com secret incorreto

        String tokenWithBearer = "Bearer " + tokenWithInvalidSignature;

        // When & Then
        String result = jwtProvider.validateToken(tokenWithBearer);
        assertTrue(result.isEmpty());
    }

    @Test
    void validateToken_WithMalformedToken_ShouldReturnEmpty() {
        // Given - Tokens malformados
        String[] malformedTokens = {
                "Bearer invalid.token.structure",
                "Bearer not-a-jwt-token",
                "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid-payload.signature",
                "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9", // Sem assinatura
                "", // Token vazio
                "   ", // Token com espaços
                "invalid-without-bearer", // Sem prefixo Bearer
        };

        // When & Then
        for (String malformedToken : malformedTokens) {
            String result = jwtProvider.validateToken(malformedToken);
            assertTrue(result.isEmpty(), 
                    "Token malformado deveria retornar vazio: " + malformedToken);
        }
    }

    @Test
    void validateToken_WithNullToken_ShouldReturnEmpty() {
        // When & Then
        String result = jwtProvider.validateToken(null);
        assertTrue(result.isEmpty());
    }

    @Test
    void validateTokenAndExtractUser_WithTokenMissingClaims_ShouldReturnNull() {
        // Given - Token sem claims obrigatórias
        Algorithm algorithm = Algorithm.HMAC256(validSecret);
        String tokenWithoutClaims = JWT.create()
                .withIssuer(validIssuer)
                .withSubject(testUserId.toString())
                // Sem claims de email e role
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(algorithm);

        String tokenWithBearer = "Bearer " + tokenWithoutClaims;

        // When & Then
        // Token pode ser válido estruturalmente, mas faltam claims
        String result = jwtProvider.validateToken(tokenWithBearer);
        assertEquals(testUserId.toString(), result);
        
        // Mas ao tentar extrair usuário completo, deve retornar null devido às claims faltantes
        var user = jwtProvider.validateTokenAndExtractUser(tokenWithBearer);
        assertNull(user);
    }

    @Test
    void validateTokenAndExtractUser_WithValidToken_ShouldReturnAuthenticatedUser() {
        // Given - Token válido com todas as claims
        Algorithm algorithm = Algorithm.HMAC256(validSecret);
        String validToken = JWT.create()
                .withIssuer(validIssuer)
                .withSubject(testUserId.toString())
                .withClaim("email", testEmail)
                .withClaim("role", testRole)
                .withExpiresAt(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .sign(algorithm);

        String tokenWithBearer = "Bearer " + validToken;

        // When
        var user = jwtProvider.validateTokenAndExtractUser(tokenWithBearer);

        // Then
        assertNotNull(user);
        assertEquals(testUserId.toString(), user.getId());
        assertEquals(testEmail, user.getEmail());
        assertEquals(testRole, user.getRole());
    }

    @Test
    void generateAccessToken_WithCustomClaims_ShouldIncludeThem() {
        UserEntity user = new UserEntity();
        user.setId(testUserId);
        user.setEmail(testEmail);
        user.setRole(UserRole.USER);

        String token = jwtProvider.generateAccessToken(user, Map.of("organizationId", "org-123"));

        Algorithm algorithm = Algorithm.HMAC256(validSecret);
        var decoded = JWT.require(algorithm)
                .withIssuer(validIssuer)
                .build()
                .verify(token);

        assertEquals("org-123", decoded.getClaim("organizationId").asString());
    }

}
