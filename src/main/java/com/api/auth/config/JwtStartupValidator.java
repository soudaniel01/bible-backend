package com.api.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.api.auth.security.jwtkeys.JwtKeyRing;
import com.api.auth.security.jwtkeys.JwtKeysProperties;

import java.util.Map;

@Component
public class JwtStartupValidator implements CommandLineRunner {

    private final JwtKeysProperties properties;
    private final String legacySecret;

    public JwtStartupValidator(JwtKeysProperties properties, @Value("${security.token.secret:}") String legacySecret) {
        this.properties = properties;
        this.legacySecret = legacySecret;
    }

    @Override
    public void run(String... args) throws Exception {
        Map<String, String> secretsByKid = JwtKeyRing.buildSecretsByKid(properties, legacySecret);

        String activeKid = properties.getActiveKid();
        String activeSecret = secretsByKid.get(activeKid);
        if (activeSecret == null) {
            throw new RuntimeException("CRITICAL SECURITY ERROR: Active JWT key is not configured. " +
                    "Please set app.jwt.keys.activeKid to a configured key (key1/key2) and provide its secret.");
        }

        validateSecret(activeKid, activeSecret);

        for (Map.Entry<String, String> entry : secretsByKid.entrySet()) {
            validateSecret(entry.getKey(), entry.getValue());
        }
    }

    private void validateSecret(String kid, String secret) {
        if (secret == null) {
            return;
        }
        if ("CHANGE_ME".equals(secret) || secret.length() < 32) {
            throw new RuntimeException("CRITICAL SECURITY ERROR: Weak or default JWT secret detected for " + kid + ". " +
                    "Please set app.jwt.keys." + kid + ".secret to a secure value with at least 32 characters.");
        }
    }
}
