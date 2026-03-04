package com.api.bible.annotations.dto;

import com.api.bible.annotations.entity.AnnotationVisibility;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CreateAnnotationRequest {
    
    @NotBlank(message = "Book ID is required")
    private String bookId;
    
    @Min(value = 1, message = "Chapter must be greater than 0")
    private int chapter;
    
    @Min(value = 1, message = "Verse start must be greater than 0")
    private int verseStart;
    
    private Integer verseEnd;
    
    @NotBlank(message = "Text is required")
    private String text;
    
    private AnnotationVisibility visibility = AnnotationVisibility.PRIVATE;
}
