package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto;

/**
 * CLASE 15 - Respuesta del login/registro: el JWT que el cliente debe guardar y enviar
 * en cada request siguiente con el header  "Authorization: Bearer <token>".
 */
public record AuthResponse(String token, String tokenType, long expiresInMs) {

    public static AuthResponse bearer(String token, long expiresInMs) {
        return new AuthResponse(token, "Bearer", expiresInMs);
    }
}
