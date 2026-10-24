package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.jwt;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * CLASE 15 - PASO 3: JwtAuthFilter. El "portero" de la API.
 *
 * Un filtro se ejecuta ANTES de que la petición llegue al controller. Este filtro mira cada
 * request y se pregunta: "¿trae un JWT válido en el header Authorization?"
 *
 *      Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...
 *
 *  - Si trae un token válido  -> autentica al usuario en el SecurityContext y deja pasar.
 *  - Si NO trae token          -> deja pasar SIN autenticar. Después, Spring Security decide:
 *                                 si el endpoint es público responde normalmente; si es privado, 401.
 *  - Si trae un token inválido -> no autentica a nadie (el endpoint privado responderá 401).
 *
 * Extiende {@link OncePerRequestFilter} para garantizar que se ejecute UNA sola vez por request.
 *
 * Nota: el JWT es "stateless" (sin estado): el servidor NO guarda los tokens en ningún lado.
 * Le basta con verificar la firma para confiar en lo que dice el token.
 *
 * ¿Por qué NO tiene @Component? Si fuera un bean, Spring Boot lo registraría automáticamente
 * como filtro global del servidor y se ejecutaría para TODAS las rutas, por fuera de la cadena
 * de Spring Security. Por eso lo creamos a mano en SecurityConfig y lo agregamos SOLO a la
 * cadena de la API con addFilterBefore(...).
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    /**
     * 1. doFilterInternal(): método principal del filtro.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);

        // Si hay token y todavía nadie autenticó esta request, lo validamos.
        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            authenticateIfValidToken(token, request);
        }

        // SIEMPRE continuamos la cadena de filtros. Quien decide si se permite o no el acceso
        // es la configuración de SecurityConfig (rutas públicas vs. protegidas).
        filterChain.doFilter(request, response);
    }

    /**
     * 2. extractToken(): saca el token del header "Authorization: Bearer <token>".
     */
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return header.substring(BEARER_PREFIX.length());
    }

    /**
     * 3. authenticateIfValidToken(): extrae el usuario del token, lo busca en la base de datos
     * y comprueba que el token sea válido para ese usuario.
     */
    private void authenticateIfValidToken(String token, HttpServletRequest request) {
        try {
            String username = jwtService.extractUsername(token);
            UserDetails user = userDetailsService.loadUserByUsername(username);
            if (jwtService.isTokenValid(token, user)) {
                setSecurityContextAuthentication(user, request);
            }
        } catch (JwtException | IllegalArgumentException | UsernameNotFoundException e) {
            // Token vencido, mal formado, con firma alterada o de un usuario inexistente.
            // No damos detalles al cliente (Clase 17: no revelar errores internos), solo lo logueamos.
            log.debug("JWT rechazado: {}", e.getMessage());
        }
    }

    /**
     * 4. setSecurityContextAuthentication(): guarda al usuario autenticado en el SecurityContext.
     * A partir de acá, para el resto de esta request, Spring "sabe" quién es el usuario y qué roles tiene.
     */
    private void setSecurityContextAuthentication(UserDetails user, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
