package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

/**
 * CLASE 15 - PASO 6: JwtService. Genera, valida y lee tokens JWT.
 *
 * Un JWT tiene 3 partes separadas por puntos:   HEADER.PAYLOAD.FIRMA
 *
 *   HEADER   -> {"alg":"HS256","typ":"JWT"}          qué algoritmo se usó para firmar
 *   PAYLOAD  -> {"sub":"user@example.com",            los datos ("claims") del usuario
 *                "roles":["ROLE_USER"],
 *                "iat":1700000000, "exp":1700003600}
 *   FIRMA    -> HMACSHA256(base64(header) + "." + base64(payload), CLAVE_SECRETA)
 *
 * ¡OJO! El header y el payload solo están codificados en Base64, NO cifrados:
 * cualquiera puede leerlos (probalo pegando un token en https://jwt.io).
 * Por eso NUNCA se pone información sensible (contraseñas, DNI, tarjetas) en el payload.
 *
 * Lo que impide que alguien modifique el token es la FIRMA: si cambiás una sola letra del
 * payload, la firma deja de coincidir y el servidor lo rechaza. Y solo quien tiene la clave
 * secreta puede generar una firma válida.
 */
@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long expirationMs;

    /**
     * La clave y la expiración se leen de la configuración (que a su vez las toma de variables
     * de entorno). Nunca se escriben en el código: ver Clase 16, gestión de secretos.
     */
    public JwtService(@Value("${app.jwt.secret}") String base64Secret,
                      @Value("${app.jwt.expiration-ms}") long expirationMs) {
        // HS256 exige una clave de al menos 256 bits (32 bytes). Keys.hmacShaKeyFor lo verifica.
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.expirationMs = expirationMs;
    }

    /** Crea un JWT firmado para el usuario, con sus roles y una fecha de expiración. */
    public String generateToken(UserDetails user) {
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        Date now = new Date();
        return Jwts.builder()
                .subject(user.getUsername())                         // "sub": a quién pertenece
                .claim("roles", roles)                               // claim personalizado
                .issuedAt(now)                                       // "iat": cuándo se emitió
                .expiration(new Date(now.getTime() + expirationMs))  // "exp": cuándo vence (¡buena práctica!)
                .signWith(signingKey)                                // firma HMAC-SHA256
                .compact();                                          // lo convierte en "xxx.yyy.zzz"
    }

    /** Devuelve el username (claim "sub") guardado en el token. */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Un token es válido si:
     *  1) la firma es correcta (lo verifica parseClaims; si no, lanza excepción),
     *  2) no está vencido (también lo verifica parseClaims),
     *  3) pertenece al usuario que estamos cargando.
     */
    public boolean isTokenValid(String token, UserDetails user) {
        try {
            String username = extractUsername(token);
            return username.equals(user.getUsername()) && user.isEnabled();
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(parseClaims(token));
    }

    /**
     * Verifica la firma y la expiración, y devuelve el payload.
     * Si el token fue alterado, está mal formado o venció, lanza una {@link JwtException}.
     */
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
