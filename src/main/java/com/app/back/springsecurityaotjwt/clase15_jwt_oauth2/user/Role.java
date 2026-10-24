package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.user;

/**
 * CLASE 15 - Roles de la aplicación.
 *
 * Un rol agrupa permisos: "qué puede hacer" un usuario (AUTORIZACIÓN).
 * - USER:  usuario común, puede consumir los endpoints protegidos.
 * - ADMIN: además puede usar los endpoints de administración (ver Clase 17, @PreAuthorize).
 *
 * Importante: Spring Security espera que los roles empiecen con el prefijo "ROLE_".
 * Ese prefijo se agrega en {@link User#getAuthorities()}, así hasRole("ADMIN") funciona.
 */
public enum Role {
    USER,
    ADMIN
}
