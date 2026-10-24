package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.credenciales;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * CLASE 16 - Guardar y recuperar credenciales externas CIFRADAS (requiere JWT).
 *
 *   POST /api/clase16/credenciales            guarda un token de API (se cifra solo al guardar)
 *   GET  /api/clase16/credenciales            lista mis credenciales con el token ENMASCARADO
 *   GET  /api/clase16/credenciales/{id}/token devuelve el token descifrado (solo al dueño)
 *   GET  /api/clase16/credenciales/como-se-ve-en-la-bd   muestra lo que REALMENTE hay en la base (cifrado)
 */
@RestController
@RequestMapping("/api/clase16/credenciales")
@Tag(name = "Clase 16 - Credenciales cifradas", description = "Datos recuperables cifrados con AES-GCM en la base de datos")
public class CredencialExternaController {

    public record NuevaCredencial(
            @NotBlank @Size(max = 50) @Pattern(regexp = "^[A-Za-z0-9 _-]+$") String servicio,
            @NotBlank @Size(max = 500) String tokenApi) {
    }

    public record CredencialVista(Long id, String servicio, String tokenEnmascarado) {
    }

    private final CredencialExternaRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public CredencialExternaController(CredencialExternaRepository repository, JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Operation(summary = "Guardar un token de API externa (se cifra con AES antes de llegar a la BD)")
    @PostMapping
    public ResponseEntity<CredencialVista> guardar(@Valid @RequestBody NuevaCredencial request, Authentication auth) {
        CredencialExterna guardada = repository.save(
                new CredencialExterna(auth.getName(), request.servicio(), request.tokenApi()));
        return ResponseEntity.status(HttpStatus.CREATED).body(toVista(guardada));
    }

    @Operation(summary = "Listar mis credenciales (token enmascarado)")
    @GetMapping
    public List<CredencialVista> listar(Authentication auth) {
        return repository.findByPropietario(auth.getName()).stream().map(this::toVista).toList();
    }

    @Operation(summary = "Recuperar el token original descifrado (solo el dueño)")
    @GetMapping("/{id}/token")
    public ResponseEntity<Map<String, String>> recuperar(@PathVariable Long id, Authentication auth) {
        return repository.findByIdAndPropietario(id, auth.getName())
                .map(c -> ResponseEntity.ok(Map.of("servicio", c.getServicio(), "tokenApi", c.getTokenApi())))
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(summary = "DIDÁCTICO: ver el contenido crudo de la columna en la BD (está cifrado)")
    @GetMapping("/como-se-ve-en-la-bd")
    public List<Map<String, Object>> comoSeVeEnLaBaseDeDatos(Authentication auth) {
        // Consulta parametrizada (el "?"): segura contra SQL Injection, ver Clase 17.
        return jdbcTemplate.queryForList(
                "SELECT id, servicio, token_api FROM credenciales_externas WHERE propietario = ?", auth.getName());
    }

    /** Nunca mostramos un secreto completo si no hace falta: solo los últimos 4 caracteres. */
    private CredencialVista toVista(CredencialExterna c) {
        String token = c.getTokenApi();
        String masked = token.length() <= 4 ? "****" : "****" + token.substring(token.length() - 4);
        return new CredencialVista(c.getId(), c.getServicio(), masked);
    }
}
