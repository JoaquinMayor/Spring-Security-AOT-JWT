package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.error;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.UsernameAlreadyExistsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.core.PropertyReferenceException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * CLASE 17 - "Nunca revelar errores del backend al usuario".
 *
 * Un stacktrace o un mensaje como "Table USUARIOS not found" o "Hibernate: column password..."
 * le regala al atacante información valiosa: qué tecnologías usamos, nombres de tablas, rutas.
 *
 * Este manejador centraliza los errores y responde con mensajes GENÉRICOS (formato estándar
 * ProblemDetail, RFC 9457). El detalle técnico se escribe en el LOG del servidor, con un
 * "errorId" para que soporte pueda encontrarlo si el usuario lo reporta.
 *
 * Extiende ResponseEntityExceptionHandler, que ya maneja los errores estándar de Spring MVC
 * (JSON mal formado, método no permitido, 404, etc.) devolviendo respuestas limpias.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** 400 - Validación (@Valid): acá SÍ conviene decir qué campo está mal, para que el usuario lo corrija. */
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers,
                                                                  HttpStatusCode status,
                                                                  WebRequest request) {
        Map<String, String> errores = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(e -> errores.putIfAbsent(e.getField(), e.getDefaultMessage()));
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Datos de entrada inválidos");
        problem.setProperty("errores", errores);
        return ResponseEntity.badRequest().body(problem);
    }

    /** 401 - Login fallido. Mismo mensaje si el usuario no existe o si la contraseña está mal. */
    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuthentication(AuthenticationException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Usuario o contraseña incorrectos");
    }

    /** 403 - Autenticado pero sin permiso (por ejemplo, @PreAuthorize("hasRole('ADMIN')")). */
    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail handleAccessDenied(AccessDeniedException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "No tenés permisos para esta operación");
    }

    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ProblemDetail handleUserExists(UsernameAlreadyExistsException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
    }

    /** 400 - Ordenamiento por un campo que no existe (?sort=campoInventado) en la paginación. */
    @ExceptionHandler(PropertyReferenceException.class)
    public ProblemDetail handleBadSort(PropertyReferenceException ex) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Campo de ordenamiento inválido");
    }

    /**
     * 400 - Datos que no se pueden procesar (ej.: texto cifrado alterado). No devolvemos ex.getMessage():
     * podría venir de una librería interna y filtrar detalles técnicos.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(IllegalArgumentException ex) {
        log.debug("Solicitud inválida: {}", ex.getMessage());
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Solicitud inválida");
    }

    /** 500 - Cualquier otro error: mensaje genérico al cliente, detalle completo solo en el log. */
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception ex) {
        String errorId = UUID.randomUUID().toString();
        log.error("Error inesperado [errorId={}]", errorId, ex);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR,
                "Ocurrió un error inesperado. Si persiste, contactá a soporte con el código indicado.");
        problem.setProperty("errorId", errorId);
        return problem;
    }
}
