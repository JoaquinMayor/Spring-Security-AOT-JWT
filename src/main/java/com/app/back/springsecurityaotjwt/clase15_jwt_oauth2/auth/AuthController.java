package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto.AuthRequest;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto.AuthResponse;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto.RegisterRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * CLASE 15 - PASO 4: AuthController. Endpoints PÚBLICOS para obtener un token.
 *
 *   POST /api/v1/auth/register  -> crea el usuario y devuelve un JWT
 *   POST /api/v1/auth/login     -> valida credenciales y devuelve un JWT
 *
 * El controller no tiene lógica: solo recibe, valida (@Valid, Clase 17) y delega en AuthService.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Clase 15 - Autenticación", description = "Registro y login: devuelven un JWT")
@SecurityRequirements // en Swagger: estos endpoints NO necesitan token
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @Operation(summary = "Registrar un usuario nuevo (rol USER)")
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @Operation(summary = "Login con email y contraseña. Devuelve un JWT")
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
