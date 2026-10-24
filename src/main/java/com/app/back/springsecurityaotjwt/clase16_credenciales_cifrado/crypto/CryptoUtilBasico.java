package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * CLASE 16 - Ejemplo de la diapositiva "Cifrado/Descifrado con AES" (versión BÁSICA).
 *
 * ⚠⚠ SOLO PARA ENTENDER LA IDEA. NO USAR EN PRODUCCIÓN. ⚠⚠
 * Sirve para ver las 3 piezas de la JCA (Cipher, SecretKeySpec, Base64), pero tiene 3 problemas
 * que conviene mostrar en clase (la versión corregida es {@link AesGcmEncryptionService}):
 *
 *  1) CLAVE HARDCODEADA: está escrita en el código. Cualquiera con acceso al repositorio
 *     (o al .jar, que se puede descompilar) puede descifrar todo. -> Debe venir de una variable de entorno/Vault.
 *  2) Cipher.getInstance("AES") usa por defecto el modo ECB: el MISMO texto produce SIEMPRE el
 *     MISMO cifrado, y bloques iguales se ven iguales. Filtra patrones. -> Usar AES/GCM.
 *  3) No detecta manipulaciones: si alguien altera el texto cifrado, se descifra "basura" sin avisar.
 *     -> GCM agrega una etiqueta de autenticación que detecta cualquier cambio.
 *
 * Probalo: cifrá dos veces "hola" y vas a obtener exactamente el mismo resultado (mala señal).
 */
public final class CryptoUtilBasico {

    private static final String SECRET_KEY = "1234567812345678"; // ❌ 16 caracteres hardcodeados (mal)

    private CryptoUtilBasico() {
    }

    public static String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES"); // ❌ equivale a "AES/ECB/PKCS5Padding"
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    public static String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)), StandardCharsets.UTF_8);
    }
}
