package com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.config;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.stereotype.Component;

/**
 * CLASE 17 - Headers (encabezados) de seguridad HTTP.
 *
 * Son "instrucciones" que el servidor le manda al NAVEGADOR en cada respuesta para que active
 * protecciones propias. Se usan desde SecurityConfig (Clase 15) en las dos cadenas de filtros.
 *
 *  | Header                     | ¿Qué hace?                                                     |
 *  |----------------------------|----------------------------------------------------------------|
 *  | Content-Security-Policy    | Lista blanca de dónde se pueden cargar scripts, estilos, etc.  |
 *  |                            | Bloquea scripts "inline" inyectados -> defensa fuerte vs. XSS  |
 *  | X-XSS-Protection           | Pide al navegador bloquear la página si detecta XSS (legado)   |
 *  | X-Frame-Options: DENY      | Prohíbe mostrar la página dentro de un <iframe> (clickjacking) |
 *  | Strict-Transport-Security  | "Usá siempre HTTPS conmigo" (solo se envía en conexiones HTTPS)|
 *  | X-Content-Type-Options     | nosniff: el navegador no "adivina" tipos de archivo            |
 *  | Referrer-Policy            | No filtrar la URL completa a otros sitios                      |
 */
@Component
public class SecurityHeadersConfig {

    /** Página de demo que se sirve SIN CSP a propósito, para ver el ataque XSS funcionando. */
    public static final String XSS_DEMO_WITHOUT_CSP = "/clase17/xss-demo-sin-csp.html";

    /**
     * Política para la parte WEB (páginas HTML, Swagger, login):
     *  default-src 'self'   -> por defecto, solo recursos de nuestro propio dominio
     *  script-src 'self'    -> solo scripts de archivos .js propios: ¡nada de <script> inline ni onerror=...!
     *  style-src 'self' 'unsafe-inline' -> estilos propios (Swagger y el login usan estilos inline)
     *  img-src 'self' data: -> imágenes propias y embebidas (iconos de Swagger)
     *  object-src 'none'    -> sin plugins (Flash, applets...)
     *  frame-ancestors 'none' -> nadie puede meter nuestra página en un iframe
     */
    private static final String WEB_CSP = "default-src 'self'; script-src 'self'; "
            + "style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
            + "frame-ancestors 'none'; form-action 'self' https://accounts.google.com https://github.com";

    /** La API solo devuelve JSON: no necesita cargar nada. La política más estricta posible. */
    private static final String API_CSP = "default-src 'none'; frame-ancestors 'none'";

    public Customizer<HeadersConfigurer<HttpSecurity>> apiHeaders() {
        return headers -> {
            commonHeaders(headers);
            headers.contentSecurityPolicy(csp -> csp.policyDirectives(API_CSP));
        };
    }

    public Customizer<HeadersConfigurer<HttpSecurity>> webHeaders() {
        return headers -> {
            commonHeaders(headers);
            // CSP en todas las páginas MENOS en la demo "sin CSP" (para mostrar la diferencia en clase).
            headers.addHeaderWriter(new DelegatingRequestMatcherHeaderWriter(
                    new NegatedRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(XSS_DEMO_WITHOUT_CSP)),
                    new ContentSecurityPolicyHeaderWriter(WEB_CSP)));
        };
    }

    private void commonHeaders(HeadersConfigurer<HttpSecurity> headers) {
        headers
                // Como en la diapositiva. Nota: los navegadores modernos ya ignoran este header
                // (OWASP hoy recomienda CSP como protección real), pero no hace daño enviarlo.
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31_536_000)) // 1 año
                .referrerPolicy(ref -> ref.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN));
        // X-Content-Type-Options: nosniff y Cache-Control ya vienen activados por defecto en Spring Security.
    }
}
