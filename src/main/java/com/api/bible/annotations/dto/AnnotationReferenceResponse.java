package com.api.bible.annotations.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AnnotationReferenceResponse {
    private String bookId;
    private int chapter;
    private int verseStart;
    private Integer verseEnd;
}
