package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.nosql;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * CLASE 17 - NoSQL INJECTION (simulación de MongoDB, sin instalar Mongo).
 *
 * En MongoDB las consultas son documentos JSON. Si dejamos que el cliente mande OBJETOS donde
 * esperamos TEXTO, puede inyectar operadores especiales como $ne (distinto de), $gt, $regex, $or:
 *
 *   Repositorio vulnerable:   @Query("{ 'username' : ?0, 'password' : ?1 }")
 *   El atacante envía:        { "username": {"$ne": null}, "password": {"$ne": null} }
 *   Consulta resultante:      { "username": {"$ne": null}, "password": {"$ne": null} }
 *                             = "cualquier usuario cuyo username y password no sean null"
 *   -> ¡Entra como el primer usuario de la colección sin saber ninguna contraseña!
 *
 * Esta clase SIMULA cómo Mongo evaluaría esa consulta sobre una colección en memoria.
 *
 * Cómo se previene:
 *   ✅ Recibir DTOs con campos String (no Map ni Object): Jackson rechaza {"$ne": null} -> 400.
 *   ✅ Consultas derivadas de Spring Data (findByUsernameAndPassword): tratan los valores como literales.
 *   ✅ Validar formato de entradas e IDs con expresiones regulares (como el ejemplo de Firestore).
 */
@RestController
@RequestMapping("/api/clase17/nosql")
@Tag(name = "Clase 17 - NoSQL Injection", description = "Simulación de inyección de operadores MongoDB")
@SecurityRequirements
public class NoSqlInjectionDemoController {

    /** Login con tipos seguros: si llega un objeto en vez de un texto, Jackson responde 400. */
    public record LoginSeguro(
            @NotBlank @Size(max = 50) @Pattern(regexp = "^[A-Za-z0-9._@-]+$") String username,
            @NotBlank @Size(max = 100) String password) {
    }

    /**
     * "Colección" simulada de Mongo. (Las contraseñas en texto plano son solo para simplificar la
     * simulación: en la vida real siempre irían hasheadas con BCrypt, Clase 16).
     */
    private static final List<Map<String, Object>> USERS_COLLECTION = List.of(
            Map.of("_id", "u1", "username", "admin", "password", "S3cr3t0!", "role", "ADMIN"),
            Map.of("_id", "u2", "username", "maria", "password", "M4ria#2024", "role", "USER"));

    private final boolean vulnerablesHabilitados;

    public NoSqlInjectionDemoController(@Value("${app.demos.vulnerables.enabled:false}") boolean vulnerablesHabilitados) {
        this.vulnerablesHabilitados = vulnerablesHabilitados;
    }

    @Operation(summary = "❌ VULNERABLE: acepta cualquier JSON (Map) y lo usa como filtro de Mongo")
    @PostMapping("/login-vulnerable")
    public ResponseEntity<Map<String, Object>> loginVulnerable(@RequestBody Map<String, Object> body) {
        if (!vulnerablesHabilitados) {
            return ResponseEntity.notFound().build();
        }
        // Equivale a @Query("{ 'username' : ?0, 'password' : ?1 }") con lo que mandó el cliente, tal cual.
        Map<String, Object> query = new java.util.LinkedHashMap<>();
        query.put("username", body.get("username"));
        query.put("password", body.get("password"));

        return USERS_COLLECTION.stream()
                .filter(doc -> matches(doc, query))
                .findFirst()
                .map(doc -> ResponseEntity.ok(Map.<String, Object>of(
                        "consultaEnviadaAMongo", query,
                        "resultado", "LOGIN EXITOSO como '" + doc.get("username") + "' (rol " + doc.get("role") + ")")))
                .orElse(ResponseEntity.status(401).body(Map.of(
                        "consultaEnviadaAMongo", query, "resultado", "Credenciales inválidas")));
    }

    @Operation(summary = "✅ SEGURO: DTO con Strings + validación (equivale a una consulta derivada)")
    @PostMapping("/login-seguro")
    public ResponseEntity<Map<String, Object>> loginSeguro(@Valid @RequestBody LoginSeguro body) {
        // Equivale a findByUsernameAndPassword(username, password): los valores son SIEMPRE literales.
        boolean ok = USERS_COLLECTION.stream().anyMatch(doc ->
                doc.get("username").equals(body.username()) && doc.get("password").equals(body.password()));
        return ok
                ? ResponseEntity.ok(Map.of("resultado", "LOGIN EXITOSO como '" + body.username() + "'"))
                : ResponseEntity.status(401).body(Map.of("resultado", "Credenciales inválidas"));
    }

    /**
     * ✅ Ejemplo Firestore: validar el ID antes de usarlo para construir una ruta o consulta.
     * Un ID como "../admin" o "users/otro" se rechaza con 400.
     */
    @Operation(summary = "✅ Validación de ID de documento con regex (ejemplo Firestore)")
    @GetMapping("/documentos/{userId}")
    public Map<String, Object> documento(@PathVariable @Pattern(regexp = "^[a-zA-Z0-9_-]{2,30}$") String userId) {
        return USERS_COLLECTION.stream()
                .filter(doc -> doc.get("_id").equals(userId))
                .findFirst()
                .map(doc -> Map.<String, Object>of("_id", doc.get("_id"), "username", doc.get("username")))
                .orElse(Map.of("mensaje", "Documento no encontrado"));
    }

    // ---------- Mini "motor Mongo" para la simulación: soporta igualdad, $ne y $gt ----------

    private static boolean matches(Map<String, Object> doc, Map<String, Object> query) {
        return query.entrySet().stream().allMatch(e -> matchesField(doc.get(e.getKey()), e.getValue()));
    }

    @SuppressWarnings("unchecked")
    private static boolean matchesField(Object docValue, Object condition) {
        if (condition instanceof Map<?, ?> operators) {
            // ¡Acá está el problema! El cliente mandó un OBJETO con operadores en lugar de un valor.
            return ((Map<String, Object>) operators).entrySet().stream().allMatch(op -> switch (op.getKey()) {
                case "$ne" -> !Objects.equals(docValue, op.getValue());
                case "$gt" -> docValue != null && String.valueOf(docValue).compareTo(String.valueOf(op.getValue())) > 0;
                default -> false;
            });
        }
        return Objects.equals(docValue, condition);
    }
}
