package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.password;

import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * CLASE 16 - Contraseñas con BCrypt + PEPPER.
 *
 * Recordemos las dos "especias":
 *  - SAL (salt):    valor ALEATORIO distinto para cada contraseña. Se guarda junto al hash.
 *                   Evita que dos usuarios con la misma contraseña tengan el mismo hash y
 *                   vuelve inútiles las "rainbow tables". ¡BCrypt ya la incluye solo!
 *  - PIMIENTA (pepper): valor SECRETO, igual para todos, que se guarda FUERA de la base de datos
 *                   (variable de entorno, Vault). Si roban la base de datos, sin el pepper los
 *                   hashes no sirven para nada.
 *
 * ¿Cómo lo aplicamos? En lugar de concatenar "password + pepper" (BCrypt solo usa los primeros
 * 72 bytes y podría ignorar parte del texto), calculamos primero un HMAC-SHA256 de la contraseña
 * usando el pepper como clave, y a ESE resultado le aplicamos BCrypt:
 *
 *      hashGuardado = BCrypt( HMAC_SHA256(pepper, password) )
 *
 * Esta clase "envuelve" a otro PasswordEncoder (BCrypt) y le agrega el pepper: patrón Decorator.
 */
public class PepperedPasswordEncoder implements PasswordEncoder {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final PasswordEncoder delegate;
    private final SecretKeySpec pepperKey;

    public PepperedPasswordEncoder(PasswordEncoder delegate, String pepper) {
        if (pepper == null || pepper.length() < 16) {
            throw new IllegalArgumentException("El pepper debe tener al menos 16 caracteres");
        }
        this.delegate = delegate;
        this.pepperKey = new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
    }

    /** Se usa al REGISTRAR: devuelve el hash que se guarda en la base de datos. */
    @Override
    public String encode(CharSequence rawPassword) {
        return delegate.encode(applyPepper(rawPassword));
    }

    /** Se usa al hacer LOGIN: compara lo que escribió el usuario con el hash guardado. */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return delegate.matches(applyPepper(rawPassword), encodedPassword);
    }

    private String applyPepper(CharSequence rawPassword) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(pepperKey);
            byte[] peppered = mac.doFinal(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(peppered); // 44 caracteres: entra en los 72 bytes de BCrypt
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("No se pudo aplicar el pepper", e);
        }
    }
}
