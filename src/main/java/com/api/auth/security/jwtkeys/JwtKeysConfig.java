package com.api.auth.security.jwtkeys;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(JwtKeysProperties.class)
public class JwtKeysConfig {

    @Bean
    JwtKeyRing jwtKeyRing(JwtKeysProperties properties, @Value("${security.token.secret:}") String legacySecret) {
        Map<String, String> secretsByKid = JwtKeyRing.buildSecretsByKid(properties, legacySecret);
        return new JwtKeyRing(properties.getActiveKid(), secretsByKid);
    }
}
