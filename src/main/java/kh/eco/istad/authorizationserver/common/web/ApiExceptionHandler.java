package kh.eco.istad.authorizationserver.common.web;

import java.util.Map;

import kh.eco.istad.authorizationserver.user.service.DuplicateUsernameException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(DuplicateUsernameException.class)
    ResponseEntity<Map<String, String>> duplicateUsername() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(Map.of("error", "username_unavailable", "message", "Username is already registered"));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HandlerMethodValidationException.class,
            HttpMessageNotReadableException.class})
    ResponseEntity<Map<String, String>> invalidInput() {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "invalid_request", "message", "Registration input is invalid"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> invalidArgument() {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "invalid_request", "message", "Registration input is invalid"));
    }
}
