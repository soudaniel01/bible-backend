package com.api.auth.token.service;

import com.api.auth.token.dto.LoginResponse;
import com.api.auth.token.dto.TokenResponse;
import com.api.auth.token.entity.RefreshTokenEntity;
import com.api.auth.token.repository.RefreshTokenRepository;
import com.api.auth.token.util.HashUtil;
import com.api.auth.token.util.TokenGenerator;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.entity.UserRole;
import com.api.auth.user.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

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
    private String testUserId;
    private String opaqueToken;
    private String tokenHash;
    private RefreshTokenEntity refreshTokenEntity;

    @BeforeEach
    void setUp() {
        // Configura propriedades
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpirationSeconds", 2592000L);
        ReflectionTestUtils.setField(refreshTokenService, "accessTokenExpirationSeconds", 1800L);

        // Dados de teste
        testUserId = UUID.randomUUID().toString();
        testUser = new UserEntity();
        testUser.setId(UUID.fromString(testUserId));
        testUser.setEmail("test@example.com");
        testUser.setRole(UserRole.USER);

        opaqueToken = "test-opaque-token-12345";
        tokenHash = "hashed-token-value";

        refreshTokenEntity = new RefreshTokenEntity();
        refreshTokenEntity.setId(UUID.randomUUID());
        refreshTokenEntity.setTokenHash(tokenHash);
        refreshTokenEntity.setUserId(UUID.fromString(testUserId));
        refreshTokenEntity.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));
        refreshTokenEntity.setRevoked(false);
    }

    @Test
    void createRefreshToken_ShouldCreateValidToken() {
        // Arrange
        String deviceInfo = "Test Device";
        when(tokenGenerator.generateOpaqueToken()).thenReturn(opaqueToken);
        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(tokenHash);
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class))).thenReturn(refreshTokenEntity);
        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(refreshTokenEntity));

        // Act
        RefreshTokenEntity result = refreshTokenService.createRefreshToken(testUserId, deviceInfo);

        // Assert
        assertNotNull(result);
        assertEquals(refreshTokenEntity, result);
        verify(tokenGenerator).generateOpaqueToken();
        verify(hashUtil).generateSHA256Hash(opaqueToken);
        verify(refreshTokenRepository).save(any(RefreshTokenEntity.class));
        verify(refreshTokenRepository).findByTokenHash(tokenHash);
    }

    @Test
    void refreshAccessToken_WithValidToken_ShouldReturnNewTokens() {
        // Arrange
        String deviceInfo = "Test Device";
        String newOpaqueToken = "new-opaque-token";
        String newTokenHash = "new-hashed-token";
        String accessToken = "new-access-token";

        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(tokenHash);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash))
                .thenReturn(Optional.of(refreshTokenEntity));
        when(tokenGenerator.generateOpaqueToken()).thenReturn(newOpaqueToken);
        when(hashUtil.generateSHA256Hash(newOpaqueToken)).thenReturn(newTokenHash);
        when(userService.findById(testUserId)).thenReturn(Optional.of(testUser));
        when(userService.generateAccessToken(testUser)).thenReturn(accessToken);
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class)))
                .thenReturn(refreshTokenEntity);

        // Act
        Optional<TokenResponse> result = refreshTokenService.refreshAccessToken(opaqueToken, deviceInfo);

        // Assert
        assertTrue(result.isPresent());
        TokenResponse tokenResponse = result.get();
        assertEquals(accessToken, tokenResponse.getAccessToken());
        assertEquals(1800L, tokenResponse.getExpiresIn());
        assertEquals(newOpaqueToken, tokenResponse.getRefreshToken());
        assertEquals(2592000L, tokenResponse.getRefreshExpiresIn());

        verify(refreshTokenRepository).save(argThat(token -> token.isRevoked())); // Token antigo revogado
        verify(refreshTokenRepository).save(argThat(token -> !token.isRevoked())); // Novo token criado
    }

    @Test
    void refreshAccessToken_WithInvalidToken_ShouldReturnEmpty() {
        // Arrange
        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(tokenHash);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash))
                .thenReturn(Optional.empty());

        // Act
        Optional<TokenResponse> result = refreshTokenService.refreshAccessToken(opaqueToken, "device");

        // Assert
        assertTrue(result.isEmpty());
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refreshAccessToken_WithExpiredToken_ShouldReturnEmpty() {
        // Arrange
        RefreshTokenEntity expiredToken = new RefreshTokenEntity();
        expiredToken.setTokenHash(tokenHash);
        expiredToken.setUserId(UUID.fromString(testUserId));
        expiredToken.setExpiresAt(Instant.now().minus(1, ChronoUnit.DAYS)); // Expirado
        expiredToken.setRevoked(false);

        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(tokenHash);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash))
                .thenReturn(Optional.of(expiredToken));

        // Act
        Optional<TokenResponse> result = refreshTokenService.refreshAccessToken(opaqueToken, "device");

        // Assert
        assertTrue(result.isEmpty());
        verify(refreshTokenRepository).save(argThat(RefreshTokenEntity::isRevoked)); // Token revogado
    }

    @Test
    void revokeRefreshToken_ShouldRevokeToken() {
        // Arrange
        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(tokenHash);
        when(refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash))
                .thenReturn(Optional.of(refreshTokenEntity));

        // Act
        refreshTokenService.revokeRefreshToken(opaqueToken);

        // Assert
        verify(refreshTokenRepository).save(argThat(RefreshTokenEntity::isRevoked));
    }

    @Test
    void revokeAllUserTokens_ShouldCallRepository() {
        // Act
        refreshTokenService.revokeAllUserTokens(testUserId);

        // Assert
        verify(refreshTokenRepository).revokeAllByUserId(UUID.fromString(testUserId));
    }

    @Test
    void createLoginResponse_ShouldReturnCompleteResponse() {
        // Arrange
        String deviceInfo = "Test Device";
        String accessToken = "access-token";
        
        when(userService.generateAccessToken(testUser)).thenReturn(accessToken);
        when(tokenGenerator.generateOpaqueToken()).thenReturn(opaqueToken);
        when(hashUtil.generateSHA256Hash(opaqueToken)).thenReturn(tokenHash);
        when(refreshTokenRepository.save(any(RefreshTokenEntity.class))).thenReturn(refreshTokenEntity);

        // Act
        LoginResponse result = refreshTokenService.createLoginResponse(testUser, deviceInfo);

        // Assert
        assertNotNull(result);
        assertEquals(accessToken, result.getAccessToken());
        assertEquals(1800L, result.getExpiresIn());
        assertEquals(opaqueToken, result.getRefreshToken());
        assertEquals(2592000L, result.getRefreshExpiresIn());
    }

    @Test
    void cleanupExpiredTokens_ShouldCallRepository() {
        // Act
        refreshTokenService.cleanupExpiredTokens();

        // Assert
        verify(refreshTokenRepository).deleteExpiredTokens(any(Instant.class));
    }

    @Test
    void findActiveTokensByUserId_ShouldCallRepository() {
        // Act
        refreshTokenService.getActiveTokensByUserId(testUserId);

        // Assert
        verify(refreshTokenRepository).findActiveTokensByUserId(eq(UUID.fromString(testUserId)), any(Instant.class));
    }
}