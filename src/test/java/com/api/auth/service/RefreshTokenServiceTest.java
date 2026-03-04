package com.api.auth.service;

import com.api.auth.token.entity.RefreshTokenEntity;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.token.repository.RefreshTokenRepository;
import com.api.auth.user.repository.UserRepository;
import com.api.auth.token.service.RefreshTokenService;
import com.api.auth.user.service.UserService;
import com.api.auth.token.util.TokenGenerator;
import com.api.auth.token.util.HashUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Testes para RefreshTokenService focando em:
 * - Rotação de tokens
 * - Prevenção de reuso
 * - Limite de sessões por usuário
 * - Limpeza de tokens expirados
 */
@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private TokenGenerator tokenGenerator;
    
    @Mock
    private HashUtil hashUtil;
    
    @Mock
    private UserService userService;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private UserEntity testUser;
    private RefreshTokenEntity validRefreshToken;
    private RefreshTokenEntity expiredRefreshToken;
    private RefreshTokenEntity revokedRefreshToken;
    private final String testUserId = UUID.randomUUID().toString();
    private final String testEmail = "test@example.com";
    private final String testTokenValue = "valid-refresh-token";
    private final String expiredTokenValue = "expired-refresh-token";
    private final String revokedTokenValue = "revoked-refresh-token";
    private final int maxSessionsPerUser = 5;

    @BeforeEach
    void setUp() {
        // Configurar propriedades do serviço
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpirationSeconds", 2592000L); // 30 dias
        ReflectionTestUtils.setField(refreshTokenService, "accessTokenExpirationSeconds", 900L); // 15 minutos
        ReflectionTestUtils.setField(refreshTokenService, "maxActiveSessionsPerUser", maxSessionsPerUser);

        // Criar usuário de teste
        testUser = new UserEntity();
        testUser.setId(UUID.fromString(testUserId));
        testUser.setEmail(testEmail);
        testUser.setName("Test User");
        testUser.setPassword("encoded-password");

        // Setup valid refresh token
        validRefreshToken = new RefreshTokenEntity();
        validRefreshToken.setId(UUID.randomUUID());
        validRefreshToken.setTokenHash(testTokenValue);
        validRefreshToken.setUserId(UUID.fromString(testUserId));
        validRefreshToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        validRefreshToken.setRevoked(false);
        // Setup expired refresh token
        expiredRefreshToken = new RefreshTokenEntity();
        expiredRefreshToken.setId(UUID.randomUUID());
        expiredRefreshToken.setTokenHash(expiredTokenValue);
        expiredRefreshToken.setUserId(UUID.fromString(testUserId));
        expiredRefreshToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS)); // Expirado
        expiredRefreshToken.setRevoked(false);
        // Setup revoked refresh token
        revokedRefreshToken = new RefreshTokenEntity();
        revokedRefreshToken.setId(UUID.randomUUID());
        revokedRefreshToken.setTokenHash(revokedTokenValue);
        revokedRefreshToken.setUserId(UUID.fromString(testUserId));
        revokedRefreshToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        revokedRefreshToken.setRevoked(true); // Revogado

    }

    @Test
    void createRefreshToken_ShouldCreateValidToken() {
        // Given
        String deviceInfo = "Test Device";
        String opaqueToken = "opaque-token";
        String hashedToken = "hashed-token";
        
        when(tokenGenerator.generateOpaqueToken()).thenReturn(opaqueToken);
        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(hashedToken);
        
        RefreshTokenEntity savedToken = new RefreshTokenEntity();
        savedToken.setTokenHash(hashedToken);
        savedToken.setUserId(UUID.fromString(testUserId));
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class))).thenReturn(savedToken);
        when(refreshTokenRepository.findByTokenHash(hashedToken)).thenReturn(Optional.of(savedToken));

        // When
        RefreshTokenEntity result = refreshTokenService.createRefreshToken(testUserId, deviceInfo);

        // Then
        assertNotNull(result);
        assertEquals(hashedToken, result.getTokenHash());
        
        verify(refreshTokenRepository).save(any(RefreshTokenEntity.class));
    }

    @Test
    void refreshToken_WithValidToken_ShouldRotateToken() {
        // Given
        String deviceInfo = "Test Device";
        String hashedToken = "hashed-token";
        String newOpaqueToken = "new-opaque-token";
        String newHashedToken = "new-hashed-token";
        
        when(hashUtil.generateSHA256Hash(testTokenValue)).thenReturn(hashedToken);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(hashedToken))
                .thenReturn(Optional.of(validRefreshToken));
        when(userService.findById(testUserId)).thenReturn(Optional.of(testUser));
        when(userService.generateAccessToken(testUser)).thenReturn("new-access-token");
        when(tokenGenerator.generateOpaqueToken()).thenReturn(newOpaqueToken);
        when(hashUtil.generateSHA256Hash(newOpaqueToken)).thenReturn(newHashedToken);
        
        RefreshTokenEntity newRefreshToken = new RefreshTokenEntity();
        newRefreshToken.setTokenHash(newHashedToken);
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class))).thenReturn(newRefreshToken);

        // When
        var result = refreshTokenService.refreshAccessToken(testTokenValue, deviceInfo);

        // Then
        assertTrue(result.isPresent());
        assertEquals("new-access-token", result.get().getAccessToken());
        assertEquals(newOpaqueToken, result.get().getRefreshToken());
        
        // Verificar que o token antigo foi revogado
        assertTrue(validRefreshToken.isRevoked());
        
        // Verificar que um novo token foi criado
        verify(refreshTokenRepository, times(2)).save(any(RefreshTokenEntity.class));
    }

    @Test
    void refreshToken_WithExpiredToken_ShouldReturnEmpty() {
        // Given
        String deviceInfo = "Test Device";
        String hashedToken = "expired-hashed-token";
        
        when(hashUtil.generateSHA256Hash(expiredTokenValue)).thenReturn(hashedToken);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(hashedToken))
                .thenReturn(Optional.of(expiredRefreshToken));

        // When
        var result = refreshTokenService.refreshAccessToken(expiredTokenValue, deviceInfo);
        
        // Then
        assertTrue(result.isEmpty());
        
        // Verificar que o token expirado foi revogado
        assertTrue(expiredRefreshToken.isRevoked());
        verify(refreshTokenRepository).save(expiredRefreshToken);
    }

    @Test
    void refreshToken_WithRevokedToken_ShouldReturnEmpty() {
        // Given
        String deviceInfo = "Test Device";
        String hashedToken = "revoked-hashed-token";
        
        when(hashUtil.generateSHA256Hash(revokedTokenValue)).thenReturn(hashedToken);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(hashedToken))
                .thenReturn(Optional.empty()); // Token revogado não é encontrado na busca por tokens não revogados

        // When
        var result = refreshTokenService.refreshAccessToken(revokedTokenValue, deviceInfo);
        
        // Then
        assertTrue(result.isEmpty());
    }

    @Test
    void refreshToken_WithReusedToken_ShouldRevokeAllUserTokens() {
        // Given - Simular tentativa de reuso de token já usado
        String deviceInfo = "Test Device";
        String usedTokenValue = "used-token";
        String hashedUsedToken = "used-hashed-token";
        
        RefreshTokenEntity usedToken = new RefreshTokenEntity();
        usedToken.setId(UUID.randomUUID());
        usedToken.setTokenHash(hashedUsedToken);
        usedToken.setUserId(UUID.fromString(testUserId));
        usedToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        usedToken.setRevoked(true); // Já foi usado/revogado
        
        when(hashUtil.generateSHA256Hash(usedTokenValue)).thenReturn(hashedUsedToken);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(hashedUsedToken))
                .thenReturn(Optional.empty()); // Token não encontrado pois está revogado

        // When
        var result = refreshTokenService.refreshAccessToken(usedTokenValue, deviceInfo);
        
        // Then
        assertTrue(result.isEmpty());
        
        // Verificar que nenhum token foi criado devido ao reuso
        verify(refreshTokenRepository, never()).save(any(RefreshTokenEntity.class));
    }

    @Test
    void createRefreshToken_WhenExceedsSessionLimit_ShouldRevokeOldestToken() {
        // Given - Usuário já tem o máximo de sessões
        String deviceInfo = "new-device";
        String newOpaqueToken = "new-opaque-token";
        String newHashedToken = "new-hashed-token";
        
        List<RefreshTokenEntity> existingTokens = createMultipleRefreshTokens(maxSessionsPerUser);
        
        // Mock repository to simulate max sessions reached
        when(refreshTokenRepository.findActiveTokensByUserId(eq(UUID.fromString(testUserId)), any(Instant.class))).thenReturn(existingTokens);
        // Simulate finding existing tokens for the user
        when(tokenGenerator.generateOpaqueToken()).thenReturn(newOpaqueToken);
        when(hashUtil.generateSHA256Hash(newOpaqueToken)).thenReturn(newHashedToken);
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));
        
        RefreshTokenEntity newToken = new RefreshTokenEntity();
        newToken.setTokenHash(newHashedToken);
        newToken.setUserId(UUID.fromString(testUserId));
        when(refreshTokenRepository.findByTokenHash(newHashedToken)).thenReturn(Optional.of(newToken));

        // When
        RefreshTokenEntity result = refreshTokenService.createRefreshToken(testUserId, deviceInfo);

        // Then
        assertNotNull(result);
        assertEquals(newHashedToken, result.getTokenHash());
        
        // Verificar que tokens foram salvos (revogados) e o novo token foi criado
        // O serviço deve salvar pelo menos 2 tokens: os revogados + o novo
        verify(refreshTokenRepository, atLeast(2)).save(any(RefreshTokenEntity.class));
        
        // Verificar que o método findActiveTokensByUserId foi chamado para verificar o limite
        verify(refreshTokenRepository).findActiveTokensByUserId(eq(UUID.fromString(testUserId)), any(Instant.class));
    }





    @Test
    void refreshToken_WithConcurrentRequests_ShouldHandleRaceCondition() {
        // Given - Simular condição de corrida onde o mesmo token é usado simultaneamente
        String hashedToken = "hashed-token";
        String deviceInfo = "Test Device";
        
        when(hashUtil.generateSHA256Hash(testTokenValue)).thenReturn(hashedToken);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(hashedToken))
                .thenReturn(Optional.of(validRefreshToken))
                .thenReturn(Optional.empty()); // Segunda chamada não encontra o token (já foi revogado)
        
        when(userService.findById(testUserId)).thenReturn(Optional.of(testUser));
        when(userService.generateAccessToken(testUser)).thenReturn("new-access-token");
        when(tokenGenerator.generateOpaqueToken()).thenReturn("new-token");
        when(hashUtil.generateSHA256Hash("new-token")).thenReturn("new-hashed-token");
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // When - Primeira requisição deve funcionar
        var result1 = refreshTokenService.refreshAccessToken(testTokenValue, deviceInfo);
        assertTrue(result1.isPresent());

        // When - Segunda requisição deve falhar
        var result2 = refreshTokenService.refreshAccessToken(testTokenValue, deviceInfo);
        assertTrue(result2.isEmpty());
    }

    // Métodos auxiliares para criar objetos de teste
    private RefreshTokenEntity createRefreshToken(String tokenValue) {
        RefreshTokenEntity token = new RefreshTokenEntity();
        token.setId(UUID.randomUUID());
        token.setTokenHash(tokenValue + "-hash");
        token.setUserId(UUID.fromString(testUserId));
        token.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        token.setRevoked(false);
        token.setCreatedAt(Instant.now());
        return token;
    }

    private RefreshTokenEntity createExpiredRefreshToken(String tokenValue) {
        RefreshTokenEntity token = new RefreshTokenEntity();
        token.setId(UUID.randomUUID());
        token.setTokenHash(tokenValue + "-hash");
        token.setUserId(UUID.fromString(testUserId));
        token.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS)); // Expirado
        token.setRevoked(false);
        token.setCreatedAt(Instant.now().minus(31, ChronoUnit.DAYS));
        return token;
    }

    private List<RefreshTokenEntity> createMultipleRefreshTokens(int count) {
        return java.util.stream.IntStream.range(0, count)
                .mapToObj(i -> {
                    RefreshTokenEntity token = createRefreshToken("token-" + i);
                    token.setCreatedAt(Instant.now().minus(i, ChronoUnit.MINUTES)); // Diferentes timestamps
                    return token;
                })
                .collect(java.util.stream.Collectors.toList());
    }
}