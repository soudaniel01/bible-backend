package com.api.auth.token.util;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Component
public class HashUtil {

    private static final String HASH_ALGORITHM = "SHA-256";

    /**
     * Gera hash SHA-256 de uma string e retorna em Base64 URL-safe
     * @param input string para gerar hash
     * @return hash SHA-256 em Base64 URL-safe
     */
    public String generateSHA256Hash(String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Input cannot be null or empty");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Verifica se um input corresponde ao hash fornecido
     * @param input string original
     * @param hash hash para comparar
     * @return true se o hash do input corresponder ao hash fornecido
     */
    public boolean verifyHash(String input, String hash) {
        if (input == null || hash == null) {
            return false;
        }
        
        try {
            String inputHash = generateSHA256Hash(input);
            return MessageDigest.isEqual(inputHash.getBytes(), hash.getBytes());
        } catch (Exception e) {
            return false;
        }
    }
}