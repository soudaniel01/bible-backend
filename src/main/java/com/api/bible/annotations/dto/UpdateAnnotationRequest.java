package com.api.bible.annotations.dto;

import com.api.bible.annotations.entity.AnnotationVisibility;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UpdateAnnotationRequest {
    
    @NotBlank(message = "Text is required")
    private String text;
    
    private AnnotationVisibility visibility;
}
