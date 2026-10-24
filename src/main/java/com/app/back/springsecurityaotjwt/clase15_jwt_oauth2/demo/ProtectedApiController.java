package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.demo;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * CLASE 15 - Endpoints PROTEGIDOS: solo responden si la request trae un JWT válido.
 *
 *   GET /api/test/authenticated     (Authorization: Bearer <token>)
 *     - token válido               -> 200 con los datos del usuario
 *     - sin token / inválido / vencido -> 401 Unauthorized
 *
 * Fijate que este controller NO tiene ningún código de seguridad: la protección la hace
 * SecurityConfig + JwtAuthFilter antes de que la request llegue acá.
 */
@RestController
@Tag(name = "Clase 15 - Endpoints protegidos", description = "Requieren header Authorization: Bearer <token>")
public class ProtectedApiController {

    private final UserRepository userRepository;

    public ProtectedApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Operation(summary = "Devuelve quién soy según el JWT enviado")
    @GetMapping("/api/test/authenticated")
    public Map<String, Object> authenticated(Authentication authentication) {
        // "authentication" lo cargó el JwtAuthFilter en el SecurityContext.
        return Map.of(
                "mensaje", "¡Token válido! Estás autenticado.",
                "usuario", authentication.getName(),
                "roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }

    @Operation(summary = "Lista de usuarios (solo emails, nunca contraseñas)")
    @GetMapping("/api/v1/usuarios")
    public List<String> usuarios() {
        return userRepository.findAll().stream().map(u -> u.getUsername()).toList();
    }
}
