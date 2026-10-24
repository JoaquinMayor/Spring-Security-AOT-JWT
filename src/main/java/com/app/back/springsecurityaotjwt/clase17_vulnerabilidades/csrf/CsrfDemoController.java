package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.csrf;

import io.swagger.v3.oas.annotations.Hidden;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.Map;

/**
 * CLASE 17 - CSRF (Cross-Site Request Forgery) en la parte WEB (con sesión/cookies).
 *
 * El ataque:
 *   1. Iniciás sesión en tu banco (el navegador guarda la cookie de sesión JSESSIONID).
 *   2. Sin cerrar sesión, entrás a un sitio malicioso que tiene oculto:
 *        <form action="https://mibanco.com/web/transferencias" method="POST"> ... </form>
 *        <script>document.forms[0].submit()</script>
 *   3. El navegador envía la petición AL BANCO y le agrega SOLO tu cookie de sesión.
 *   4. El banco ve una sesión válida y hace la transferencia. ¡Vos nunca hiciste clic!
 *
 * La defensa: TOKEN CSRF. El servidor genera un valor secreto y aleatorio que la página legítima
 * debe reenviar en cada operación que modifica datos (POST/PUT/DELETE). El sitio malicioso no
 * puede leerlo (el navegador le impide leer cookies y respuestas de otro dominio), así que su
 * petición llega sin token y Spring Security la rechaza con 403.
 *
 * En esta app el token se guarda en la cookie XSRF-TOKEN y el JavaScript propio lo reenvía en el
 * header X-XSRF-TOKEN (patrón "double submit": cookie + header). Ver SecurityConfig, cadena web.
 *
 * Probalo en: http://localhost:8080/clase17/csrf-demo.html
 *
 * ¿Y las APIs con JWT? No necesitan CSRF porque el token viaja en el header Authorization, que
 * el navegador nunca agrega solo. Por eso en la cadena /api/** está csrf.disable().
 */
@RestController
@RequestMapping("/web")
@Hidden
public class CsrfDemoController {

    public record Transferencia(
            @NotBlank @Size(max = 34) String destino,
            @NotNull @DecimalMin("0.01") BigDecimal monto) {
    }

    /**
     * Devuelve el token CSRF actual. Al leerlo, Spring además escribe la cookie XSRF-TOKEN.
     * (El token se genera de forma "diferida": solo cuando alguien lo necesita).
     */
    @GetMapping("/csrf-token")
    public Map<String, String> csrfToken(CsrfToken token, Authentication auth) {
        return Map.of("usuario", auth.getName(), "headerName", token.getHeaderName(), "token", token.getToken());
    }

    /** Operación "peligrosa" que modifica datos: exige sesión + token CSRF válido. */
    @PostMapping("/transferencias")
    public Map<String, Object> transferir(@Valid @RequestBody Transferencia t, Authentication auth) {
        return Map.of(
                "resultado", "Transferencia realizada (simulada)",
                "usuario", auth.getName(),
                "destino", t.destino(),
                "monto", t.monto());
    }
}
