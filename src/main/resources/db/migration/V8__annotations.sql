-- Tabela de anotações bíblicas
CREATE TABLE bible_annotations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    book_id VARCHAR(50) NOT NULL,
    chapter INT NOT NULL,
    verse_start INT NOT NULL,
    verse_end INT,
    text TEXT NOT NULL,
    visibility VARCHAR(20) NOT NULL DEFAULT 'PRIVATE',
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT fk_annotations_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT chk_chapter_positive CHECK (chapter > 0),
    CONSTRAINT chk_verse_start_positive CHECK (verse_start > 0),
    CONSTRAINT chk_verse_range CHECK (verse_end IS NULL OR verse_end >= verse_start)
);

-- Índices para performance
CREATE INDEX idx_annotations_user_status_created ON bible_annotations(user_id, status, created_at);
CREATE INDEX idx_annotations_user_passage ON bible_annotations(user_id, book_id, chapter, verse_start, verse_end);
CREATE INDEX idx_annotations_user_book_chapter ON bible_annotations(user_id, book_id, chapter);
