package com.app.back.springsecurityaotjwt.clase15_jwt_oauth2.auth;

/**
 * CLASE 15 - Se lanza cuando alguien intenta registrarse con un email que ya existe.
 * El GlobalExceptionHandler (Clase 17) la convierte en una respuesta 409 CONFLICT.
 */
public class UsernameAlreadyExistsException extends RuntimeException {

    public UsernameAlreadyExistsException() {
        super("El usuario ya existe");
    }
}
