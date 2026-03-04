package com.api.bible.annotations.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "bible_annotations", indexes = {
    @Index(name = "idx_annotations_user_status_created", columnList = "user_id, status, created_at"),
    @Index(name = "idx_annotations_user_passage", columnList = "user_id, book_id, chapter, verse_start, verse_end"),
    @Index(name = "idx_annotations_user_book_chapter", columnList = "user_id, book_id, chapter")
})
@Getter
@Setter
public class BibleAnnotationEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "book_id", nullable = false, length = 50)
    private String bookId;

    @Column(nullable = false)
    private Integer chapter;

    @Column(name = "verse_start", nullable = false)
    private Integer verseStart;

    @Column(name = "verse_end")
    private Integer verseEnd;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String text;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AnnotationVisibility visibility = AnnotationVisibility.PRIVATE;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AnnotationStatus status = AnnotationStatus.ACTIVE;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;
}
