package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.config;

import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.jwt.JwtAuthFilter;
import com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.jwt.JwtService;
import com.app.back.springsecurityaotjwt.clase17_vulnerabilidades.config.SecurityHeadersConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * CLASE 15 - PASO 5: SecurityConfig. Acá se decide QUIÉN puede entrar a CADA ruta.
 *
 * Toda request pasa por una "cadena de filtros" (SecurityFilterChain) antes de llegar al controller.
 * Esta aplicación tiene DOS cadenas, porque conviven dos mundos distintos:
 *
 *  ┌──────────────────────────────┬──────────────────────────────────────────────┐
 *  │ 1) API REST  (/api/**)       │ 2) Aplicación web (todo lo demás)            │
 *  ├──────────────────────────────┼──────────────────────────────────────────────┤
 *  │ Autenticación con JWT        │ Login con Google/GitHub (OAuth2) o formulario│
 *  │ STATELESS: sin sesión        │ Con sesión (cookie JSESSIONID)               │
 *  │ CSRF deshabilitado (*)       │ CSRF HABILITADO (Clase 17)                   │
 *  └──────────────────────────────┴──────────────────────────────────────────────┘
 *
 * (*) ¿Por qué se puede deshabilitar CSRF en la API? Porque el JWT viaja en el header
 *     Authorization, que el navegador NUNCA agrega solo. Un sitio malicioso no puede
 *     "colgarse" de la sesión del usuario. En cambio, las cookies SÍ se envían solas,
 *     por eso la parte web necesita protección CSRF. (Detalle completo en la Clase 17).
 *
 * @Order indica el orden de evaluación: primero se prueba la cadena de la API; si la URL no
 * empieza con /api/, se usa la cadena web.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** Rutas de la API que NO necesitan token. */
    public static final String[] API_WHITE_LIST = {
            "/api/v1/auth/**",          // Clase 15: login y registro
            "/api/clase16/demo/**",     // Clase 16: demos de hashing y cifrado
            "/api/clase17/sql/**",      // Clase 17: demos de SQL Injection
            "/api/clase17/nosql/**"     // Clase 17: demos de NoSQL Injection
    };

    /** Rutas web públicas (páginas, Swagger, recursos estáticos). */
    public static final String[] WEB_WHITE_LIST = {
            "/", "/error", "/favicon.ico",
            "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**",
            "/clase17/**"               // páginas HTML de demostración de XSS y CSRF
    };

    // =========================================================================================
    //  CADENA 1: API REST con JWT
    // =========================================================================================
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http,
                                                      JwtService jwtService,
                                                      UserDetailsService userDetailsService,
                                                      SecurityHeadersConfig securityHeaders) throws Exception {
        http
                // Esta cadena solo atiende URLs que empiezan con /api/
                .securityMatcher("/api/**")

                // Reglas de acceso: se evalúan de ARRIBA hacia ABAJO, gana la primera que coincide.
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(API_WHITE_LIST).permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/clase17/comentarios/**").permitAll()
                        .anyRequest().authenticated()      // todo lo demás exige un JWT válido
                )

                // Sin sesión: cada request debe traer su token. El servidor no "recuerda" a nadie.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // CSRF deshabilitado: el JWT viaja en un header, no en una cookie (ver Clase 17).
                .csrf(csrf -> csrf.disable())

                // CORS: qué frontends (otros dominios) pueden llamar a esta API desde el navegador.
                .cors(Customizer.withDefaults())

                // Headers de seguridad (CSP, X-Frame-Options, HSTS...). Detalle en la Clase 17.
                .headers(securityHeaders.apiHeaders())

                // Sin token (o token inválido) en ruta protegida -> 401 Unauthorized.
                // (sin esto, Spring respondería 403, que en realidad significa "no tenés permiso").
                .exceptionHandling(ex -> ex.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))

                // Nuestro filtro JWT se ejecuta ANTES del filtro estándar de usuario/contraseña.
                .addFilterBefore(new JwtAuthFilter(jwtService, userDetailsService),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // =========================================================================================
    //  CADENA 2: Aplicación web con OAuth2 (Google/GitHub) + formulario de login
    // =========================================================================================
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http,
                                                      SecurityHeadersConfig securityHeaders) throws Exception {
        // Clase 17: el token CSRF se guarda en una cookie "XSRF-TOKEN" legible por JavaScript
        // (withHttpOnlyFalse) para que un frontend pueda leerlo y reenviarlo en el header X-XSRF-TOKEN.
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(WEB_WHITE_LIST).permitAll()
                        .anyRequest().authenticated()
                )

                // Login social: Spring genera solo las URLs /oauth2/authorization/google y /github.
                // Después de un login exitoso redirige a /profile.
                .oauth2Login(oauth -> oauth.defaultSuccessUrl("/profile", true))

                // Formulario de login por defecto de Spring Security en /login
                // (sirve para entrar con los usuarios de la base de datos, ej. user@example.com).
                .formLogin(form -> form.defaultSuccessUrl("/profile", true))

                // Logout: invalida la sesión, limpia la autenticación y borra la cookie de sesión.
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID"))

                // CSRF HABILITADO (Clase 17): acá sí hay cookie de sesión, así que es necesario.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler))

                .headers(securityHeaders.webHeaders());

        return http.build();
    }

    /**
     * CORS (Cross-Origin Resource Sharing): por defecto el navegador bloquea que una página de
     * http://localhost:3000 llame a una API en http://localhost:8080. Acá autorizamos
     * explícitamente qué orígenes (frontends) pueden hacerlo. NUNCA usar "*" con credenciales.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:5173"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }
}
