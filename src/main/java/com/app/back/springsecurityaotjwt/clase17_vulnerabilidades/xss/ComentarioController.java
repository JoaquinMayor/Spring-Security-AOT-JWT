package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.xss;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.time.Instant;
import java.util.List;

/**
 * CLASE 17 - XSS (Cross-Site Scripting) en una API REST.
 *
 * El ataque, paso a paso:
 *   1. El atacante publica el comentario:   <img src=x onerror="alert('XSS')">
 *   2. La API lo guarda y lo devuelve tal cual en el JSON.
 *   3. El frontend lo pinta con  elemento.innerHTML = comentario.texto
 *   4. El navegador interpreta el HTML y EJECUTA el JavaScript en la sesión de cada víctima
 *      (puede robar tokens, hacer acciones en su nombre, cambiar la página...).
 *
 * Defensas en capas (ninguna sola alcanza):
 *   ✅ Validar la ENTRADA: @Valid + @Size en el DTO (largo máximo, campos obligatorios).
 *   ✅ Escapar la SALIDA: HtmlUtils.htmlEscape convierte  <  en  &lt;  ->  se muestra como texto, no se ejecuta.
 *   ✅ En el frontend: usar textContent (o frameworks como React/Angular que escapan por defecto), no innerHTML.
 *   ✅ Content-Security-Policy (SecurityHeadersConfig): aunque todo lo anterior falle, el navegador
 *      se niega a ejecutar scripts inline.
 *
 * Probalo visualmente en:  http://localhost:8080/clase17/xss-demo.html
 */
@RestController
@RequestMapping("/api/clase17/comentarios")
@Tag(name = "Clase 17 - XSS", description = "Validación de entrada y escape de salida")
public class ComentarioController {

    public record NuevoComentario(@NotBlank @Size(max = 500) String texto) {
    }

    public record ComentarioDto(Long id, String autor, String texto, Instant fechaCreacion) {
    }

    private final ComentarioRepository repository;

    public ComentarioController(ComentarioRepository repository) {
        this.repository = repository;
    }

    @Operation(summary = "Publicar un comentario (requiere JWT)")
    @PostMapping
    public ResponseEntity<ComentarioDto> publicar(@Valid @RequestBody NuevoComentario body, Authentication auth) {
        // Guardamos el texto ORIGINAL y escapamos al MOSTRARLO: así el escape se adapta a
        // dónde se muestre (HTML, JSON, PDF...) y no "rompemos" los datos guardados.
        Comentario c = repository.save(new Comentario(auth.getName(), body.texto()));
        return ResponseEntity.status(HttpStatus.CREATED).body(escapado(c));
    }

    @Operation(summary = "✅ Comentarios con la salida ESCAPADA (seguro)")
    @SecurityRequirements
    @GetMapping
    public List<ComentarioDto> listar() {
        return repository.findTop50ByOrderByFechaCreacionDesc().stream().map(this::escapado).toList();
    }

    @Operation(summary = "❌ Comentarios SIN escapar (para la demo de XSS)")
    @SecurityRequirements
    @GetMapping("/sin-escapar")
    public List<ComentarioDto> listarSinEscapar() {
        return repository.findTop50ByOrderByFechaCreacionDesc().stream()
                .map(c -> new ComentarioDto(c.getId(), c.getAutor(), c.getTexto(), c.getFechaCreacion()))
                .toList();
    }

    private ComentarioDto escapado(Comentario c) {
        return new ComentarioDto(c.getId(), HtmlUtils.htmlEscape(c.getAutor()),
                HtmlUtils.htmlEscape(c.getTexto()), c.getFechaCreacion());
    }
}
