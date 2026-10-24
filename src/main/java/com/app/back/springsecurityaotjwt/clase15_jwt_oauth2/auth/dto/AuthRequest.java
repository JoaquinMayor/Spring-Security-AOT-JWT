package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * CLASE 15 - Datos que envía el cliente para hacer login:  POST /api/v1/auth/login
 *
 * Las anotaciones de validación son parte de la Clase 17 ("validación del lado del servidor"):
 * si el cliente manda un email vacío o mal formado, la request se rechaza con 400 ANTES de
 * llegar a la lógica de negocio. Nunca confiamos en que el frontend haya validado.
 */
public record AuthRequest(
        @NotBlank @Email String username,
        @NotBlank @Size(max = 100) String password
) {
}
