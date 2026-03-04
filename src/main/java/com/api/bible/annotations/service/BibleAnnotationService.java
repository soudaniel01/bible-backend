package com.api.bible.annotations.service;

import com.api.bible.annotations.dto.*;
import com.api.bible.annotations.entity.*;
import com.api.bible.annotations.repository.BibleAnnotationRepository;
import com.api.auth.exception.BusinessException;
import com.api.auth.security.AuthenticatedUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class BibleAnnotationService {

    @Autowired
    private BibleAnnotationRepository repository;

    private UUID getCurrentUserId() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof AuthenticatedUser) {
            return UUID.fromString(((AuthenticatedUser) principal).getId());
        }
        throw new BusinessException("Usuário não autenticado", "UNAUTHORIZED", 401);
    }

    @Transactional
    public AnnotationResponse create(CreateAnnotationRequest request) {
        if (request.getVerseEnd() != null && request.getVerseEnd() < request.getVerseStart()) {
            throw new BusinessException("O verso final deve ser maior ou igual ao verso inicial", "INVALID_RANGE", 400);
        }

        BibleAnnotationEntity entity = new BibleAnnotationEntity();
        entity.setUserId(getCurrentUserId());
        entity.setBookId(request.getBookId());
        entity.setChapter(request.getChapter());
        entity.setVerseStart(request.getVerseStart());
        entity.setVerseEnd(request.getVerseEnd());
        entity.setText(request.getText());
        if (request.getVisibility() != null) {
            entity.setVisibility(request.getVisibility());
        }

        return new AnnotationResponse(repository.save(entity));
    }

    @Transactional(readOnly = true)
    public List<AnnotationResponse> findAll(String bookId, Integer chapter, Integer verse, AnnotationStatus status) {
        return repository.findByUserIdAndFilters(getCurrentUserId(), status, bookId, chapter, verse)
                .stream()
                .map(AnnotationResponse::new)
                .collect(Collectors.toList());
    }
    
    @Transactional(readOnly = true)
    public List<AnnotationReferenceResponse> findReferences(AnnotationStatus status) {
        return repository.findDistinctReferences(getCurrentUserId(), status);
    }

    @Transactional
    public AnnotationResponse update(UUID id, UpdateAnnotationRequest request) {
        BibleAnnotationEntity entity = getEntityOrThrow(id);
        
        entity.setText(request.getText());
        if (request.getVisibility() != null) {
            entity.setVisibility(request.getVisibility());
        }
        
        return new AnnotationResponse(repository.save(entity));
    }

    @Transactional
    public AnnotationResponse archive(UUID id) {
        BibleAnnotationEntity entity = getEntityOrThrow(id);
        entity.setStatus(AnnotationStatus.ARCHIVED);
        return new AnnotationResponse(repository.save(entity));
    }

    @Transactional
    public AnnotationResponse unarchive(UUID id) {
        BibleAnnotationEntity entity = getEntityOrThrow(id);
        entity.setStatus(AnnotationStatus.ACTIVE);
        return new AnnotationResponse(repository.save(entity));
    }

    @Transactional
    public void delete(UUID id) {
        BibleAnnotationEntity entity = getEntityOrThrow(id);
        repository.delete(entity);
    }

    private BibleAnnotationEntity getEntityOrThrow(UUID id) {
        return repository.findByIdAndUserId(id, getCurrentUserId())
                .orElseThrow(() -> new BusinessException("Anotação não encontrada", "NOT_FOUND", 404));
    }
}
