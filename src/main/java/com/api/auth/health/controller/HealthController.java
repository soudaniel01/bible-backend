package com.api.auth.health.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller para endpoints de health check da aplicação.
 * Fornece informações sobre o status da aplicação.
 */
@RestController
@RequestMapping("/api")
@Tag(name = "Health", description = "Endpoints para verificação de saúde da aplicação")
public class HealthController {

    /**
     * Endpoint de health check da aplicação.
     * Retorna informações básicas sobre o status da aplicação.
     *
     * @return ResponseEntity com informações de saúde da aplicação
     */
    @GetMapping("/health")
    @Operation(
        summary = "Health Check",
        description = "Verifica se a aplicação está funcionando corretamente"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Aplicação está funcionando corretamente")
    })
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> healthInfo = new HashMap<>();
        healthInfo.put("status", "UP");
        healthInfo.put("timestamp", LocalDateTime.now());
        healthInfo.put("service", "auth-api");
        healthInfo.put("version", "1.0.0");
        
        return ResponseEntity.ok(healthInfo);
    }
}