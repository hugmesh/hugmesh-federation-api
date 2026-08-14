package net.hugmesh.federation.web;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Reactive ({@code @RestControllerAdvice}) mapper that turns jakarta Bean
 * Validation failures into a clean {@code 400 Bad Request} with per-field errors,
 * so a malformed request to ANY endpoint surfaces as a structured client error
 * instead of a 500 or a raw R2DBC data-integrity error from a DB CHECK / NOT NULL.
 *
 * <p>Two WebFlux failure shapes are handled:
 * <ul>
 *   <li>{@link WebExchangeBindException} — a {@code @Valid @RequestBody} DTO whose
 *       field constraints ({@code @NotBlank}, {@code @Pattern}, {@code @Size}, …)
 *       failed; the binding result carries the field errors;</li>
 *   <li>{@link ConstraintViolationException} — a {@code @Validated} controller's
 *       {@code @PathVariable}/{@code @RequestParam} constraint
 *       ({@code @Pattern}, {@code @NotBlank}, …) failed; the path of the violation
 *       is the parameter name.</li>
 * </ul>
 *
 * <p>Body shape: {@code {"error":"validation failed","fields":{<name>:<message>}}}
 * — the {@code error} key matches the platform UIs' convention; {@code fields}
 * lists the offending fields so the WYSIWYG / admin forms can highlight them. This
 * advice is additive: it does NOT touch {@link org.springframework.web.server.ResponseStatusException}
 * (the existing owner-enforcement / not-found mapping), which Spring already
 * renders with its declared status.
 */
@RestControllerAdvice
public class ValidationExceptionHandler {

    /** A {@code @Valid @RequestBody} DTO failed field validation. */
    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, Object>> handleBodyValidation(WebExchangeBindException ex) {
        Map<String, String> fields = new TreeMap<>();
        for (FieldError fe : ex.getFieldErrors()) {
            fields.putIfAbsent(fe.getField(), message(fe));
        }
        return badRequest(fields);
    }

    /** A {@code @Validated} {@code @PathVariable}/{@code @RequestParam} failed. */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleParamValidation(ConstraintViolationException ex) {
        Map<String, String> fields = new TreeMap<>();
        for (ConstraintViolation<?> v : ex.getConstraintViolations()) {
            fields.putIfAbsent(lastNode(v), v.getMessage());
        }
        return badRequest(fields);
    }

    /**
     * A malformed/missing body or an unparseable param (e.g. a non-numeric
     * {@code {id}} that should be a {@code Long}, or a missing required body) —
     * surface as 400, not 500. {@link WebExchangeBindException} subclasses this, so
     * the more specific handler above wins for DTO field validation.
     */
    @ExceptionHandler(ServerWebInputException.class)
    public ResponseEntity<Map<String, Object>> handleInput(ServerWebInputException ex) {
        String reason = ex.getReason() == null ? "malformed request" : ex.getReason();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("detail", reason);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    private static ResponseEntity<Map<String, Object>> badRequest(Map<String, String> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("fields", fields);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    private static String message(FieldError fe) {
        return fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage();
    }

    /** The leaf property of a constraint-violation path = the param/field name. */
    private static String lastNode(ConstraintViolation<?> v) {
        String path = v.getPropertyPath().toString();
        int dot = path.lastIndexOf('.');
        return dot >= 0 ? path.substring(dot + 1) : path;
    }
}
