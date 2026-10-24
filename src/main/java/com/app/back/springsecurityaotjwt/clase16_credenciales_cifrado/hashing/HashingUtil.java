package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.hashing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * CLASE 16 - HASHING con la Java Cryptography Architecture (JCA): clase {@link MessageDigest}.
 *
 * Un hash es una "huella digital" de los datos:
 *  - Siempre tiene el mismo tamaño (SHA-256 -> 256 bits = 64 caracteres hex), sin importar la entrada.
 *  - Es UNIDIRECCIONAL: del hash NO se puede volver al dato original. No hay "deshashear".
 *  - Es determinista: el mismo dato da siempre el mismo hash.
 *  - Efecto avalancha: cambiar UNA letra cambia el hash por completo.
 *  - NO usa clave.
 *
 * ¿Para qué sirve? Para verificar INTEGRIDAD (que un archivo/mensaje no fue modificado),
 * firmas digitales, blockchain... y, con cuidado, contraseñas.
 *
 * ⚠ SHA-256 es RÁPIDO, y para contraseñas eso es un problema: una GPU calcula miles de millones
 *   de SHA-256 por segundo, así que un atacante puede probar diccionarios enteros. Para contraseñas
 *   usá BCrypt (ver PasswordEncoderConfig). SHA-256 queda para integridad de datos.
 * ⚠ MD5 y SHA-1 están ROTOS: no los uses para nada relacionado con seguridad.
 */
public final class HashingUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    private HashingUtil() {
    }

    /**
     * Ejemplo de la diapositiva: hash SHA-256 codificado en Base64.
     * Dos usuarios con la contraseña "123456" tendrán EXACTAMENTE el mismo hash (problema: sin sal).
     */
    public static String sha256Base64(String data) {
        return Base64.getEncoder().encodeToString(sha256(data.getBytes(StandardCharsets.UTF_8)));
    }

    /** Lo mismo pero en hexadecimal, el formato que suelen mostrar las herramientas (sha256sum). */
    public static String sha256Hex(String data) {
        return HexFormat.of().formatHex(sha256(data.getBytes(StandardCharsets.UTF_8)));
    }

    /** Genera una SAL: bytes aleatorios criptográficamente seguros (SecureRandom, nunca Random). */
    public static String generateSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * SHA-256 con SAL: hash(sal + dato). La sal se guarda junto al hash (no es secreta).
     * Ahora dos datos iguales producen hashes distintos, porque cada uno tiene su propia sal.
     */
    public static String sha256WithSalt(String data, String base64Salt) {
        byte[] salt = Base64.getDecoder().decode(base64Salt);
        byte[] input = data.getBytes(StandardCharsets.UTF_8);
        byte[] salted = new byte[salt.length + input.length];
        System.arraycopy(salt, 0, salted, 0, salt.length);
        System.arraycopy(input, 0, salted, salt.length, input.length);
        return Base64.getEncoder().encodeToString(sha256(salted));
    }

    /**
     * Verificación de integridad: ¿el contenido sigue siendo el mismo que cuando calculamos el hash?
     * Se compara en "tiempo constante" (MessageDigest.isEqual) para no dar pistas por el tiempo de respuesta.
     */
    public static boolean verifyIntegrity(String data, String expectedSha256Hex) {
        byte[] actual = sha256(data.getBytes(StandardCharsets.UTF_8));
        byte[] expected = HexFormat.of().parseHex(expectedSha256Hex);
        return MessageDigest.isEqual(actual, expected);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            // Todas las JVM están obligadas a soportar SHA-256, así que esto no debería pasar nunca.
            throw new IllegalStateException(e);
        }
    }
}
