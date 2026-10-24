package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.privilegios;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * CLASE 17 - Principio de MÍNIMO PRIVILEGIO con @PreAuthorize.
 *
 *   - Con el token de user@example.com  -> 403 Forbidden (autenticado, pero sin permiso)
 *   - Con el token de admin@example.com -> 200 OK
 *
 * Recordá la diferencia:
 *   401 Unauthorized = "no sé quién sos" (falta token o es inválido)
 *   403 Forbidden    = "sé quién sos, pero no podés hacer esto"
 */
@RestController
@RequestMapping("/api/clase17/admin")
@Tag(name = "Clase 17 - Mínimo privilegio", description = "Endpoints solo para ADMIN con @PreAuthorize")
public class AdminController {

    private final UserRepository userRepository;

    public AdminController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Operation(summary = "Usuarios con sus roles (solo ADMIN)")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/usuarios")
    public List<Map<String, Object>> usuarios() {
        return userRepository.findAll().stream()
                .map(u -> Map.<String, Object>of("id", u.getId(), "username", u.getUsername(), "roles", u.getRoles()))
                .toList();
    }
}
