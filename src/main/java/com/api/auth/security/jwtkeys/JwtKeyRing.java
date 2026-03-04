package com.api.auth.security.jwtkeys;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.springframework.util.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtKeyRing {

    private final String activeKid;
    private final Map<String, Algorithm> algorithmsByKid;

    public JwtKeyRing(String activeKid, Map<String, String> secretsByKid) {
        this.activeKid = activeKid;
        this.algorithmsByKid = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : secretsByKid.entrySet()) {
            if (StringUtils.hasText(entry.getKey()) && StringUtils.hasText(entry.getValue())) {
                this.algorithmsByKid.put(entry.getKey(), Algorithm.HMAC256(entry.getValue()));
            }
        }
    }

    public String getActiveKid() {
        return activeKid;
    }

    public Algorithm getActiveAlgorithm() {
        Algorithm algorithm = algorithmsByKid.get(activeKid);
        if (algorithm == null) {
            throw new IllegalStateException("Active JWT key not configured: " + activeKid);
        }
        return algorithm;
    }

    public DecodedJWT verify(String token) {
        List<Algorithm> candidates = resolveCandidateAlgorithms(token);
        JWTVerificationException last = null;

        for (Algorithm algorithm : candidates) {
            try {
                return JWT.require(algorithm)
                        .withIssuer("auth-api")
                        .acceptLeeway(Duration.ofSeconds(2).getSeconds())
                        .build()
                        .verify(token);
            } catch (JWTVerificationException e) {
                last = e;
            }
        }

        if (last != null) {
            throw last;
        }
        throw new JWTVerificationException("No JWT keys configured");
    }

    private List<Algorithm> resolveCandidateAlgorithms(String token) {
        String kid = null;
        try {
            kid = JWT.decode(token).getKeyId();
        } catch (Exception ignored) {
        }

        if (StringUtils.hasText(kid)) {
            Algorithm algorithm = algorithmsByKid.get(kid);
            if (algorithm != null) {
                return List.of(algorithm);
            }
        }

        List<Algorithm> candidates = new ArrayList<>();
        Algorithm active = algorithmsByKid.get(activeKid);
        if (active != null) {
            candidates.add(active);
        }
        for (Algorithm algorithm : algorithmsByKid.values()) {
            if (!candidates.contains(algorithm)) {
                candidates.add(algorithm);
            }
        }
        return candidates;
    }

    public static Map<String, String> buildSecretsByKid(JwtKeysProperties properties, String legacySecret) {
        Map<String, String> secrets = new LinkedHashMap<>();

        String key1Configured = normalizeSecret(properties.getKey1().getSecret());
        String legacy = normalizeSecret(legacySecret);
        String key1Effective = key1Configured;
        if (!StringUtils.hasText(key1Effective) || "CHANGE_ME".equals(key1Effective)) {
            key1Effective = legacy;
        }
        String key1Secret = normalizeSecret(key1Effective);
        if (StringUtils.hasText(key1Secret)) {
            secrets.put("key1", key1Secret);
        }

        String key2Secret = normalizeSecret(properties.getKey2().getSecret());
        if (StringUtils.hasText(key2Secret)) {
            secrets.put("key2", key2Secret);
        }

        return secrets;
    }

    private static String firstNonBlank(String a, String b) {
        return StringUtils.hasText(a) ? a : b;
    }

    private static String normalizeSecret(String secret) {
        if (!StringUtils.hasText(secret)) {
            return null;
        }
        String trimmed = secret.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public static String normalizeKid(String kid) {
        if (!StringUtils.hasText(kid)) {
            return null;
        }
        return kid.trim().toLowerCase(Locale.ROOT);
    }
}
