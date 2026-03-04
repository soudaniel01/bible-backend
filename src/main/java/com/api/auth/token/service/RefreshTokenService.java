package com.api.auth.token.service;

import com.api.auth.exception.BusinessException;
import com.api.auth.token.dto.LoginResponse;
import com.api.auth.token.dto.TokenResponse;
import com.api.auth.token.entity.RefreshTokenEntity;
import com.api.auth.token.repository.RefreshTokenRepository;
import com.api.auth.token.util.HashUtil;
import com.api.auth.token.util.TokenGenerator;
import com.api.auth.user.entity.UserEntity;
import com.api.auth.user.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenGenerator tokenGenerator;
    private final HashUtil hashUtil;
    private final UserService userService;

    @Value("${app.jwt.refresh-expiration:2592000}") // 30 dias em segundos
    private long refreshTokenExpirationSeconds;

    @Value("${app.jwt.access-expiration:900}") // 15 minutos em segundos
    private long accessTokenExpirationSeconds;

    @Value("${app.jwt.max-active-sessions:5}") // Máximo de sessões ativas por usuário
    private int maxActiveSessionsPerUser;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                             TokenGenerator tokenGenerator,
                             HashUtil hashUtil,
                             UserService userService) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.hashUtil = hashUtil;
        this.userService = userService;
    }

    /**
     * Cria um novo refresh token para o usuário
     * Retorna um array onde [0] é o token opaco e [1] é a entidade salva
     */
    @Transactional
    public String[] createRefreshTokenWithOpaque(String userId, String deviceInfo) {
        // Aplica limite de sessões ativas antes de criar novo token
        enforceActiveSessionLimit(userId);
        
        // Gera token opaco
        String opaqueToken = tokenGenerator.generateOpaqueToken();
        String tokenHash = hashUtil.generateSHA256Hash(opaqueToken);
        
        // Calcula expiração
        Instant expiresAt = Instant.now().plus(refreshTokenExpirationSeconds, ChronoUnit.SECONDS);
        
        // Cria e salva entidade
        RefreshTokenEntity refreshToken = new RefreshTokenEntity(tokenHash, UUID.fromString(userId), expiresAt, deviceInfo);
        refreshTokenRepository.save(refreshToken);
        
        return new String[]{opaqueToken, tokenHash};
    }
    
    /**
     * Cria um novo refresh token para o usuário (método legado)
     */
    @Transactional
    public RefreshTokenEntity createRefreshToken(String userId, String deviceInfo) {
        String[] result = createRefreshTokenWithOpaque(userId, deviceInfo);
        String tokenHash = result[1];
        
        return refreshTokenRepository.findByTokenHash(tokenHash).orElseThrow();
    }

    /**
     * Valida e rotaciona um refresh token
     */
    @Transactional
    public Optional<TokenResponse> refreshAccessToken(String opaqueRefreshToken, String deviceInfo) {
        String tokenHash = hashUtil.generateSHA256Hash(opaqueRefreshToken);
        
        Optional<RefreshTokenEntity> tokenOpt = refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash);
        
        if (tokenOpt.isEmpty()) {
            // Token não encontrado ou já revogado - possível reuso
            handleTokenReuse(opaqueRefreshToken);
            return Optional.empty();
        }
        
        RefreshTokenEntity currentToken = tokenOpt.get();
        
        // Verifica se o token expirou
        if (currentToken.isExpired()) {
            revokeToken(currentToken);
            return Optional.empty();
        }
        
        // Token válido - procede com rotação
        String userId = currentToken.getUserId().toString();
        
        // Revoga o token atual
        revokeToken(currentToken);
        
        // Cria novo refresh token
        String[] tokenResult = createRefreshTokenWithOpaque(userId, deviceInfo);
        String newOpaqueToken = tokenResult[0]; // Token opaco real
        
        // Gera novo access token
        UserEntity user = userService.findById(userId)
            .orElseThrow(() -> new BusinessException("User not found", "USER_NOT_FOUND", 404));
        
        String newAccessToken = userService.generateAccessToken(user);
        
        return Optional.of(new TokenResponse(
            newAccessToken,
            accessTokenExpirationSeconds,
            newOpaqueToken,
            refreshTokenExpirationSeconds
        ));
    }

    /**
     * Revoga um refresh token específico
     */
    @Transactional
    public void revokeRefreshToken(String opaqueRefreshToken) {
        String tokenHash = hashUtil.generateSHA256Hash(opaqueRefreshToken);
        
        Optional<RefreshTokenEntity> tokenOpt = refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash);
        tokenOpt.ifPresent(this::revokeToken);
    }
    
    /**
     * Revoga todos os tokens de um usuário baseado em um refresh token válido
     */
    @Transactional
    public boolean revokeAllUserTokensByRefreshToken(String opaqueRefreshToken) {
        String tokenHash = hashUtil.generateSHA256Hash(opaqueRefreshToken);
        
        Optional<RefreshTokenEntity> tokenOpt = refreshTokenRepository.findByTokenHashAndRevokedFalse(tokenHash);
        if (tokenOpt.isPresent()) {
            String userId = tokenOpt.get().getUserId().toString();
            revokeAllUserTokens(userId);
            return true;
        }
        return false;
    }

    /**
     * Revoga todos os refresh tokens de um usuário
     */
    @Transactional
    public void revokeAllUserTokens(String userId) {
        refreshTokenRepository.revokeAllByUserId(UUID.fromString(userId));
    }

    /**
     * Cria resposta de login com access e refresh tokens
     */
    public LoginResponse createLoginResponse(UserEntity user, String deviceInfo) {
        String accessToken = userService.generateAccessToken(user);
        String[] tokenResult = createRefreshTokenWithOpaque(user.getId().toString(), deviceInfo);
        String opaqueRefreshToken = tokenResult[0]; // Token opaco real
        
        return new LoginResponse(
            accessToken,
            accessTokenExpirationSeconds,
            opaqueRefreshToken,
            refreshTokenExpirationSeconds
        );
    }

    /**
     * Lida com possível reuso de token revogado
     * Política de segurança: ao detectar reuso, revoga todos os tokens ativos do usuário
     */
    private void handleTokenReuse(String opaqueRefreshToken) {
        String tokenHash = hashUtil.generateSHA256Hash(opaqueRefreshToken);
        
        // Tenta encontrar o token revogado para identificar o usuário
        Optional<RefreshTokenEntity> revokedTokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);
        
        if (revokedTokenOpt.isPresent()) {
            String userId = revokedTokenOpt.get().getUserId().toString();
            
            // Política de segurança: revoga todos os tokens ativos do usuário
            revokeAllUserTokens(userId);
            
            logger.warn("Token reuse detected for user {}. All active tokens revoked for security.", userId);
        } else {
            // Token não encontrado no banco - possível tentativa de ataque
            logger.warn("Possible token reuse detected with unknown token. No userId to revoke.");
        }
    }

    /**
     * Revoga um token específico
     */
    private void revokeToken(RefreshTokenEntity token) {
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    /**
     * Aplica o limite de sessões ativas por usuário
     * Se o usuário exceder o limite, revoga os tokens mais antigos
     */
    @Transactional
    private void enforceActiveSessionLimit(String userId) {
        Instant now = Instant.now();
        List<RefreshTokenEntity> activeTokens = refreshTokenRepository.findActiveTokensByUserId(UUID.fromString(userId), now);
        
        // Se já atingiu o limite máximo, revoga os mais antigos
        if (activeTokens.size() >= maxActiveSessionsPerUser) {
            int tokensToRevoke = activeTokens.size() - maxActiveSessionsPerUser + 1; // +1 para dar espaço ao novo token
            
            activeTokens.stream()
                .sorted(Comparator.comparing(RefreshTokenEntity::getCreatedAt)) // Ordena pelos mais antigos primeiro
                .limit(tokensToRevoke)
                .forEach(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
                
            logger.info("Revoked {} old tokens for user {} to enforce session limit of {}",
                tokensToRevoke, userId, maxActiveSessionsPerUser);
        }
    }

    /**
     * Conta quantos tokens ativos um usuário possui
     */
    public long countActiveTokensByUserId(String userId) {
        return refreshTokenRepository.countActiveTokensByUserId(UUID.fromString(userId), Instant.now());
    }

    /**
     * Lista todos os tokens ativos de um usuário (útil para administração)
     */
    public List<RefreshTokenEntity> getActiveTokensByUserId(String userId) {
        return refreshTokenRepository.findActiveTokensByUserId(UUID.fromString(userId), Instant.now());
    }

    /**
     * Limpa tokens expirados (pode ser chamado por job agendado)
     */
    @Transactional
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(Instant.now());
    }
}
