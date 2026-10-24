package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.sqlinjection;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * CLASE 17 - Demos de SQL Injection (públicas, para probar en clase).
 *
 * Probá con nombre = Teclado  y después con  nombre = x' OR '1'='1
 *   GET /api/clase17/sql/vulnerable?nombre=...   -> el ataque funciona
 *   GET /api/clase17/sql/seguro?nombre=...       -> el ataque NO funciona (devuelve [])
 *   GET /api/clase17/sql/seguro-jpa?nombre=...   -> el ataque NO funciona (devuelve [])
 *
 * El endpoint vulnerable solo existe si app.demos.vulnerables.enabled=true (apagado en "prod").
 */
@RestController
@RequestMapping("/api/clase17/sql")
@Tag(name = "Clase 17 - SQL Injection", description = "Comparación consulta concatenada vs. parametrizada")
@SecurityRequirements
public class SqlInjectionDemoController {

    private final SqlInjectionDemoService service;
    private final boolean vulnerablesHabilitados;

    public SqlInjectionDemoController(SqlInjectionDemoService service,
                                      @Value("${app.demos.vulnerables.enabled:false}") boolean vulnerablesHabilitados) {
        this.service = service;
        this.vulnerablesHabilitados = vulnerablesHabilitados;
    }

    @Operation(summary = "❌ VULNERABLE: SQL armado concatenando strings")
    @GetMapping("/vulnerable")
    public ResponseEntity<List<Map<String, Object>>> vulnerable(@RequestParam String nombre) {
        if (!vulnerablesHabilitados) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(service.buscarVulnerable(nombre));
    }

    @Operation(summary = "✅ SEGURO: consulta parametrizada (JDBC PreparedStatement)")
    @GetMapping("/seguro")
    public List<Map<String, Object>> seguro(@RequestParam @NotBlank @Size(max = 100) String nombre) {
        return service.buscarSeguroJdbc(nombre);
    }

    @Operation(summary = "✅ SEGURO: consulta derivada de Spring Data JPA")
    @GetMapping("/seguro-jpa")
    public List<ProductoDto> seguroJpa(@RequestParam @NotBlank @Size(max = 100) String nombre) {
        return service.buscarSeguroJpa(nombre);
    }
}
