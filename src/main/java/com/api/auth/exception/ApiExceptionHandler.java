package com.api.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.validation.FieldError;
import org.springframework.dao.DataIntegrityViolationException;
import org.postgresql.util.PSQLException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.security.sasl.AuthenticationException;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(ApiExceptionHandler.class);
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "Unauthorized",
            "Email/Senha invalido",
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUsernameNotFound(UsernameNotFoundException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "Unauthorized",
            ex.getMessage(),
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(AuthenticationException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "Unauthorized",
            ex.getMessage(),
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.FORBIDDEN,
            "Forbidden",
            "Acesso negado",
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
        Map<String, String> validationErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            validationErrors.put(fieldName, errorMessage);
        });
        
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.BAD_REQUEST,
            "Bad Request",
            "Dados de entrada inválidos",
            getPath(request)
        );
        errorResponse.put("validationErrors", validationErrors);
        
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.BAD_REQUEST,
            "Bad Request",
            ex.getMessage(),
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<Map<String, Object>> handleBusinessException(BusinessException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.valueOf(ex.getHttpStatus()),
            ex.getErrorCode(),
            ex.getMessage(),
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.valueOf(ex.getHttpStatus()));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(DataIntegrityViolationException ex, WebRequest request) {
        String code = "DATA_INTEGRITY_VIOLATION";
        String message = "Dados inválidos. Verifique os campos e tente novamente.";
        boolean isEmailConflict = false;

        Throwable cause = ex.getRootCause();
        if (cause instanceof PSQLException) {
            PSQLException psqlEx = (PSQLException) cause;
            if ("23505".equals(psqlEx.getSQLState())) {
                if (psqlEx.getServerErrorMessage() != null && 
                    psqlEx.getServerErrorMessage().getConstraint() != null &&
                    psqlEx.getServerErrorMessage().getConstraint().contains("users_email_key")) {
                    isEmailConflict = true;
                }
            }
        }
        
        if (!isEmailConflict) {
            String specificMessage = ex.getMostSpecificCause().getMessage();
            if (specificMessage != null && 
               (specificMessage.contains("users_email_key") || 
                specificMessage.contains("duplicate key value violates unique constraint") ||
                specificMessage.contains("Unique index or primary key violation"))) {
                isEmailConflict = true;
            }
        }

        if (isEmailConflict) {
            code = "EMAIL_ALREADY_EXISTS";
            message = "Este e-mail já está cadastrado.";
            logger.warn("Conflict: Email already exists for path {}", getPath(request));
        } else {
            logger.error("Data integrity violation", ex);
        }

        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.CONFLICT,
            "Conflict",
            message,
            getPath(request)
        );
        errorResponse.put("code", code);
        
        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "Erro interno do servidor",
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex, WebRequest request) {
        Map<String, Object> errorResponse = createErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "Erro interno do servidor",
            getPath(request)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private Map<String, Object> createErrorResponse(HttpStatus status, String error, String message, String path) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now().format(TIMESTAMP_FORMATTER));
        errorResponse.put("status", status.value());
        errorResponse.put("error", error);
        errorResponse.put("message", message);
        errorResponse.put("path", path);
        return errorResponse;
    }

    private String getPath(WebRequest request) {
        String path = request.getDescription(false);
        if (path.startsWith("uri=")) {
            return path.substring(4);
        }
        return path;
    }
}