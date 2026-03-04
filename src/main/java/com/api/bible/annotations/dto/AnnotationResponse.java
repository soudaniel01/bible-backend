package com.api.bible.annotations.dto;

import com.api.bible.annotations.entity.AnnotationStatus;
import com.api.bible.annotations.entity.AnnotationVisibility;
import com.api.bible.annotations.entity.BibleAnnotationEntity;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@NoArgsConstructor
public class AnnotationResponse {
    private UUID id;
    private String bookId;
    private int chapter;
    private int verseStart;
    private Integer verseEnd;
    private String text;
    private AnnotationVisibility visibility;
    private AnnotationStatus status;
    private Instant createdAt;
    private Instant updatedAt;

    public AnnotationResponse(BibleAnnotationEntity entity) {
        this.id = entity.getId();
        this.bookId = entity.getBookId();
        this.chapter = entity.getChapter();
        this.verseStart = entity.getVerseStart();
        this.verseEnd = entity.getVerseEnd();
        this.text = entity.getText();
        this.visibility = entity.getVisibility();
        this.status = entity.getStatus();
        this.createdAt = entity.getCreatedAt();
        this.updatedAt = entity.getUpdatedAt();
    }
}
