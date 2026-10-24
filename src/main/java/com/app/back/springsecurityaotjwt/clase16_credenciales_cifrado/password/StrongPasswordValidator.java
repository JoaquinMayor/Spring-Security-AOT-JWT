package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.password;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

/**
 * CLASE 16 - Lógica de la anotación {@link StrongPassword}.
 *
 * La expresión regular exige:
 *   (?=.*[a-z])        al menos una minúscula
 *   (?=.*[A-Z])        al menos una mayúscula
 *   (?=.*\d)           al menos un número
 *   (?=.*[^A-Za-z0-9]) al menos un símbolo
 *   .{8,64}            entre 8 y 64 caracteres
 */
public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    private static final Pattern STRONG =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,64}$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        // null lo maneja @NotBlank; acá solo validamos la fortaleza.
        return value == null || STRONG.matcher(value).matches();
    }
}
