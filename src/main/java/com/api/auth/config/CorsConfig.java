package com.api.auth.config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

    private static final List<String> REQUIRED_ALLOWED_ORIGINS = List.of(
            "http://localhost:4173",
            "http://localhost:8081",
            "http://localhost:5173",
            "http://127.0.0.1:4173",
            "http://127.0.0.1:8081",
            "http://127.0.0.1:5173",
            "http://138.197.94.166:8089"
    );

    @Value("${frontend.allowed.origins:http://localhost:4173,http://localhost:8081,http://localhost:5173,http://127.0.0.1:4173,http://127.0.0.1:8081,http://127.0.0.1:5173}")
    private String allowedOriginsProperty;

    private List<String> allowedOrigins;

    @PostConstruct
    public void init() {
        List<String> parsedOrigins = Arrays.stream(allowedOriginsProperty.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        LinkedHashSet<String> merged = new LinkedHashSet<>();
        merged.addAll(parsedOrigins);
        merged.addAll(REQUIRED_ALLOWED_ORIGINS);

        allowedOrigins = List.copyOf(merged);

        System.out.println("CORS allowed origins: " + allowedOrigins);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration cfg = new CorsConfiguration();

        cfg.setAllowedOrigins(allowedOrigins);

        cfg.setAllowedMethods(List.of(
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS"
        ));

        cfg.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With"
        ));

        cfg.setExposedHeaders(List.of(
                "Authorization",
                "Location"
        ));

        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", cfg);

        return source;
    }
}
