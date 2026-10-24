package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.password;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * CLASE 16 - Anotación de validación propia: "la contraseña debe ser fuerte".
 *
 * Buena práctica: validar la fortaleza de las contraseñas (mínimo 8 caracteres, con números y
 * símbolos). De nada sirve el mejor algoritmo de hash si el usuario elige "123456": un atacante
 * lo adivina en el primer intento.
 *
 * Uso:  public record RegisterRequest(@StrongPassword String password) {}
 */
@Documented
@Constraint(validatedBy = StrongPasswordValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
public @interface StrongPassword {

    String message() default "La contraseña debe tener entre 8 y 64 caracteres e incluir mayúsculas, "
            + "minúsculas, números y símbolos";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
