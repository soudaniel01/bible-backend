package com.api.bible.annotations.repository;

import com.api.bible.annotations.dto.AnnotationReferenceResponse;
import com.api.bible.annotations.entity.AnnotationStatus;
import com.api.bible.annotations.entity.BibleAnnotationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface BibleAnnotationRepository extends JpaRepository<BibleAnnotationEntity, UUID> {

    @Query("SELECT b FROM BibleAnnotationEntity b WHERE b.userId = :userId " +
           "AND (:status IS NULL OR b.status = :status) " +
           "AND (:bookId IS NULL OR b.bookId = :bookId) " +
           "AND (:chapter IS NULL OR b.chapter = :chapter) " +
           "AND (:verse IS NULL OR (b.verseStart <= :verse AND (b.verseEnd IS NULL OR b.verseEnd >= :verse))) " +
           "ORDER BY b.createdAt DESC")
    List<BibleAnnotationEntity> findByUserIdAndFilters(
            @Param("userId") UUID userId,
            @Param("status") AnnotationStatus status,
            @Param("bookId") String bookId,
            @Param("chapter") Integer chapter,
            @Param("verse") Integer verse);

    @Query("SELECT DISTINCT new com.api.bible.annotations.dto.AnnotationReferenceResponse(b.bookId, b.chapter, b.verseStart, b.verseEnd) " +
           "FROM BibleAnnotationEntity b " +
           "WHERE b.userId = :userId " +
           "AND (:status IS NULL OR b.status = :status) " +
           "ORDER BY b.bookId, b.chapter, b.verseStart")
    List<AnnotationReferenceResponse> findDistinctReferences(
            @Param("userId") UUID userId,
            @Param("status") AnnotationStatus status);
            
    boolean existsByIdAndUserId(UUID id, UUID userId);
    
    // Método para buscar por ID e UserID para garantir ownership no update/delete
    java.util.Optional<BibleAnnotationEntity> findByIdAndUserId(UUID id, UUID userId);
}
