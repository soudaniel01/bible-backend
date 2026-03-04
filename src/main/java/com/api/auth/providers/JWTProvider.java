package com.api.auth.providers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.api.auth.security.AuthenticatedUser;
import com.api.auth.security.jwtkeys.JwtKeyRing;

import java.time.Duration;
import java.time.Instant;
import com.api.auth.user.entity.UserEntity;
import java.util.Map;
import org.springframework.util.StringUtils;

@Service
public class JWTProvider {

        private static final Logger log = LoggerFactory.getLogger(JWTProvider.class);

        private final JwtKeyRing jwtKeyRing;

        @Value("${app.jwt.access-expiration:900}") // 15 minutos em segundos por padrão
        private long accessTokenExpirationSeconds;

	@Value("${app.security.require-tenant-claim:false}")
	private boolean requireTenantClaim;

        public JWTProvider(JwtKeyRing jwtKeyRing) {
                this.jwtKeyRing = jwtKeyRing;
        }

	/**
	 * Gera access token para um usuário
	 */
	public String generateAccessToken(UserEntity user) {
		return generateAccessToken(user, Map.of());
	}

	public String generateAccessToken(UserEntity user, Map<String, String> customClaims) {
		var builder = JWT.create()
                                .withKeyId(jwtKeyRing.getActiveKid())
				.withIssuer("auth-api")
				.withExpiresAt(Instant.now().plusSeconds(accessTokenExpirationSeconds))
				.withSubject(user.getId().toString())
				.withClaim("email", user.getEmail())
				.withClaim("role", user.getRole().name());

		if (customClaims != null && !customClaims.isEmpty()) {
			for (var entry : customClaims.entrySet()) {
				if (entry.getKey() != null && entry.getValue() != null) {
					builder.withClaim(entry.getKey(), entry.getValue());
				}
			}
		}

		return builder.sign(jwtKeyRing.getActiveAlgorithm());
	}
	
        public String validateToken(String token) {
		
            if (token == null || token.trim().isEmpty()) {
                log.warn("Token ausente ou vazio.");
                return "";
            }
		
            if (!token.startsWith("Bearer ")) {
                log.warn("Token malformado: esperado prefixo 'Bearer '.");
                return "";
            }
	    
	    token = token.replace("Bearer ", "").trim();
		
	    // Verifica se tem 3 partes separadas por ponto (header.payload.signature)
            if (token.split("\\.").length != 3) {
                log.warn("Token inválido: não possui 3 partes.");
                return "";
            }
		
                try {
                        DecodedJWT decodedJWT = jwtKeyRing.verify(token);

						if (requireTenantClaim && !StringUtils.hasText(decodedJWT.getClaim("tenantId").asString())) {
							log.warn("Token inválido");
							return "";
						}

						var subject = decodedJWT.getSubject();
                        return subject;
                } catch(TokenExpiredException e) {
                        log.warn("Token expirado");
                        return "";
                } catch(JWTVerificationException e) {
                        log.warn("Token inválido");
                        return "";
                }
		
	}
	
	/**
	 * Valida o token e extrai as informações completas do usuário autenticado
	 * @param token Token JWT com prefixo Bearer
	 * @return AuthenticatedUser com id, email e role ou null se inválido
	 */
	public AuthenticatedUser validateTokenAndExtractUser(String token) {
		
		if (token == null || token.trim().isEmpty()) {
			log.warn("Token ausente ou vazio.");
			return null;
		}
		
		if (!token.startsWith("Bearer ")) {
			log.warn("Token malformado: esperado prefixo 'Bearer '.");
			return null;
		}
		
		token = token.replace("Bearer ", "").trim();
		
		// Verifica se tem 3 partes separadas por ponto (header.payload.signature)
		if (token.split("\\.").length != 3) {
			log.warn("Token inválido: não possui 3 partes.");
			return null;
		}
		
		try {
			DecodedJWT decodedJWT = jwtKeyRing.verify(token);
			
			String userId = decodedJWT.getSubject();
			String email = decodedJWT.getClaim("email").asString();
			String role = decodedJWT.getClaim("role").asString();
			String tenantId = decodedJWT.getClaim("tenantId").asString();
			
			// Para compatibilidade com tokens antigos que podem não ter as claims
			if (email == null || role == null) {
				log.warn("Token não possui claims email/role - possivelmente token antigo");
				return null;
			}

			if (requireTenantClaim && !StringUtils.hasText(tenantId)) {
				log.warn("Token inválido");
				return null;
			}
			
			return new AuthenticatedUser(userId, email, role);
			
		} catch(TokenExpiredException e) {
			log.warn("Token expirado");
			return null;
		} catch(JWTVerificationException e) {
			log.warn("Token inválido");
			return null;
		}
	}
	
}
