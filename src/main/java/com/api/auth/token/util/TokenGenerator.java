package com.api.auth.token.util;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TokenGenerator {

    private static final int TOKEN_LENGTH = 64; // 64 bytes = 512 bits
    private final SecureRandom secureRandom;

    public TokenGenerator() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * Gera um token opaco aleatório seguro
     * @return String base64 URL-safe do token gerado
     */
    public String generateOpaqueToken() {
        byte[] tokenBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Gera um token opaco com tamanho customizado
     * @param length tamanho em bytes do token
     * @return String base64 URL-safe do token gerado
     */
    public String generateOpaqueToken(int length) {
        if (length < 32) {
            throw new IllegalArgumentException("Token length must be at least 32 bytes for security");
        }
        
        byte[] tokenBytes = new byte[length];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}