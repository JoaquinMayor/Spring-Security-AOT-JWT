package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth.dto;

import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.password.StrongPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * CLASE 15 - Datos para registrar un usuario nuevo:  POST /api/v1/auth/register
 *
 * @StrongPassword viene de la Clase 16: obliga a que la contraseña tenga al menos 8 caracteres,
 * mayúsculas, minúsculas, números y símbolos ("validar la fortaleza de las contraseñas").
 */
public record RegisterRequest(
        @NotBlank @Email String username,
        @NotBlank @StrongPassword String password
) {
}
