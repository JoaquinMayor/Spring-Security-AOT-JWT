package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.oauth2;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * CLASE 15 - PASO 3 (OAuth2): controlador de la parte WEB (usa sesión, no JWT).
 *
 * ¿Qué es OAuth2? Un protocolo que permite que una aplicación acceda a recursos EN NOMBRE de
 * un usuario SIN conocer su contraseña. Ejemplo: "Iniciar sesión con Google".
 *
 *   1. El usuario entra a /login y elige "Google".
 *   2. Spring lo redirige a Google (/oauth2/authorization/google).
 *   3. El usuario se loguea EN GOOGLE (nuestra app nunca ve su contraseña) y acepta los permisos.
 *   4. Google redirige de vuelta a /login/oauth2/code/google con un "código".
 *   5. Spring cambia ese código por un access token y pide los datos del usuario (nombre, email).
 *   6. El usuario queda autenticado en nuestra app (con sesión) y se lo redirige a /profile.
 *
 * Todo ese ida y vuelta lo hace Spring Security gracias a .oauth2Login() en SecurityConfig.
 */
@RestController
@Hidden // no se muestra en Swagger: es la parte web, no la API REST
public class OAuth2Controller {

    /** Página pública. */
    @GetMapping("/")
    public Map<String, String> home() {
        return Map.of(
                "mensaje", "Bienvenido a las Clases 15, 16 y 17 de Seguridad en Java",
                "login", "/login  (formulario o Google/GitHub)",
                "swagger", "/swagger-ui.html",
                "demoXss", "/clase17/xss-demo.html",
                "demoCsrf", "/clase17/csrf-demo.html");
    }

    /** Saludo personalizado. Funciona tanto con login social (OAuth2) como con formulario. */
    @GetMapping("/welcome")
    public String welcome(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauth) {
            // Con OAuth2, los datos del usuario vienen del proveedor (Google, GitHub) como "atributos".
            return "Hola " + oauth.getPrincipal().getAttributes().get("name")
                    + " (te logueaste con " + oauth.getAuthorizedClientRegistrationId() + ")";
        }
        return "Hola " + authentication.getName() + " (te logueaste con usuario y contraseña)";
    }

    /**
     * Datos del usuario logueado. Ojo: NO devolvemos el objeto Principal completo, porque en el
     * login por formulario contiene el hash de la contraseña. Exponer de más es una vulnerabilidad.
     */
    @GetMapping({"/user", "/profile"})
    public Map<String, Object> profile(Authentication authentication) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("nombre", authentication.getName());
        data.put("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        if (authentication instanceof OAuth2AuthenticationToken oauth) {
            data.put("proveedor", oauth.getAuthorizedClientRegistrationId());
            data.put("atributosDelProveedor", oauth.getPrincipal().getAttributes());
        } else {
            data.put("proveedor", "formulario (base de datos local)");
        }
        return data;
    }
}
