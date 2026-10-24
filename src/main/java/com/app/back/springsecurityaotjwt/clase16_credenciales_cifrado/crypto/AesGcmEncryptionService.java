package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * CLASE 16 - CIFRADO SIMÉTRICO con AES-256-GCM (la forma correcta).
 *
 * Cifrado simétrico = la MISMA clave cifra y descifra. Es REVERSIBLE: lo usamos cuando
 * necesitamos RECUPERAR el dato original más adelante, por ejemplo:
 *   ✔ un token de acceso a una API externa (lo tenemos que volver a enviar)
 *   ✔ datos sensibles que hay que mostrar: DNI, número de tarjeta, etc.
 *   ✘ contraseñas de usuarios -> NUNCA se cifran, se HASHEAN (no necesitamos recuperarlas).
 *
 * Piezas de la JCA que usamos:
 *   - KeyGenerator: genera claves secretas aleatorias.
 *   - SecretKey / SecretKeySpec: representa la clave.
 *   - Cipher: el que cifra (ENCRYPT_MODE) y descifra (DECRYPT_MODE).
 *
 * ¿Por qué GCM y no "AES" a secas (ver CryptoUtilBasico)?
 *   - Usa un IV (vector de inicialización) ALEATORIO en cada cifrado: el mismo texto cifrado dos
 *     veces da resultados distintos. No se filtran patrones.
 *   - Agrega una etiqueta de autenticación: si alguien modifica el texto cifrado, al descifrar
 *     se lanza una excepción en vez de devolver basura.
 *
 * El IV no es secreto: lo guardamos pegado al principio del texto cifrado -> Base64( IV + cifrado ).
 */
@Service
public class AesGcmEncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;   // tamaño recomendado para GCM
    private static final int TAG_LENGTH_BITS = 128;  // tamaño de la etiqueta de autenticación

    private final SecretKey key;
    private final SecureRandom secureRandom = new SecureRandom();

    /** La clave viene de la configuración (variable de entorno AES_KEY), nunca del código. */
    public AesGcmEncryptionService(@Value("${app.crypto.aes-key}") String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("La clave AES debe tener 32 bytes (AES-256) codificados en Base64");
        }
        this.key = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(String plainText) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv); // IV nuevo y aleatorio en CADA cifrado

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] result = ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array();
            return Base64.getEncoder().encodeToString(result);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Error al cifrar", e);
        }
    }

    public String decrypt(String base64CipherText) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(Base64.getDecoder().decode(base64CipherText));
            byte[] iv = new byte[IV_LENGTH_BYTES];
            buffer.get(iv);
            byte[] cipherText = new byte[buffer.remaining()];
            buffer.get(cipherText);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            return new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException | java.nio.BufferUnderflowException e) {
            // Clave incorrecta, dato manipulado o mal formado: GCM lo detecta.
            throw new IllegalArgumentException("No se pudo descifrar: el dato fue alterado o la clave no es correcta");
        }
    }

    /**
     * Cómo generar una clave AES-256 nueva con KeyGenerator (para la variable de entorno AES_KEY).
     * Alternativa por consola:  openssl rand -base64 32
     */
    public static String generateNewBase64Key() {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256);
            return Base64.getEncoder().encodeToString(generator.generateKey().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
