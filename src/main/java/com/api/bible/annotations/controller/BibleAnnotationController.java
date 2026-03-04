package com.api.bible.annotations.controller;

import com.api.bible.annotations.dto.*;
import com.api.bible.annotations.entity.AnnotationStatus;
import com.api.bible.annotations.service.BibleAnnotationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/annotations")
@Tag(name = "Bible Annotations", description = "Operações de anotações bíblicas")
@SecurityRequirement(name = "bearerAuth")
public class BibleAnnotationController {

    @Autowired
    private BibleAnnotationService service;

    @PostMapping
    @Operation(summary = "Criar nova anotação")
    public ResponseEntity<AnnotationResponse> create(@RequestBody @Valid CreateAnnotationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(request));
    }

    @GetMapping
    @Operation(summary = "Listar anotações do usuário com filtros")
    public ResponseEntity<List<AnnotationResponse>> findAll(
            @RequestParam(required = false) String bookId,
            @RequestParam(required = false) Integer chapter,
            @RequestParam(required = false) Integer verse,
            @RequestParam(required = false, defaultValue = "ACTIVE") AnnotationStatus status) {
        return ResponseEntity.ok(service.findAll(bookId, chapter, verse, status));
    }

    @GetMapping("/references")
    @Operation(summary = "Listar referências distintas com anotações")
    public ResponseEntity<List<AnnotationReferenceResponse>> findReferences(
            @RequestParam(required = false, defaultValue = "ACTIVE") AnnotationStatus status) {
        return ResponseEntity.ok(service.findReferences(status));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Atualizar anotação")
    public ResponseEntity<AnnotationResponse> update(
            @PathVariable UUID id,
            @RequestBody @Valid UpdateAnnotationRequest request) {
        return ResponseEntity.ok(service.update(id, request));
    }

    @PatchMapping("/{id}/archive")
    @Operation(summary = "Arquivar anotação")
    public ResponseEntity<AnnotationResponse> archive(@PathVariable UUID id) {
        return ResponseEntity.ok(service.archive(id));
    }

    @PatchMapping("/{id}/unarchive")
    @Operation(summary = "Desarquivar anotação")
    public ResponseEntity<AnnotationResponse> unarchive(@PathVariable UUID id) {
        return ResponseEntity.ok(service.unarchive(id));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Excluir anotação permanentemente")
    public ResponseEntity<Map<String, String>> delete(@PathVariable UUID id) {
        service.delete(id);
        return ResponseEntity.ok(Map.of("message", "Anotação excluída permanentemente. Esta ação não pode ser desfeita."));
    }
}
