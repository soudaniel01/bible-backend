package com.api.auth.security.ratelimit;

import java.time.Clock;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
@ConditionalOnProperty(prefix = "app.security.ratelimit", name = "enabled", havingValue = "true", matchIfMissing = true)
public class RateLimitConfig {

    @Bean
    Clock rateLimitClock() {
        return Clock.systemUTC();
    }

    @Bean
    RateLimitService rateLimitService(RateLimitProperties properties) {
        return new RateLimitService(properties);
    }

    @Bean
    LoginPenaltyService loginPenaltyService(Clock rateLimitClock, RateLimitProperties properties) {
        return new LoginPenaltyService(rateLimitClock, properties);
    }

    @Bean
    RateLimitFilter rateLimitFilter(
            RateLimitProperties properties,
            RateLimitService rateLimitService,
            LoginPenaltyService loginPenaltyService,
            ObjectMapper objectMapper) {
        return new RateLimitFilter(properties, rateLimitService, loginPenaltyService, objectMapper);
    }
}
