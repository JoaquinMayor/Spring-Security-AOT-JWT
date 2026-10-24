package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

/**
 * CLASE 16 - Cifrado TRANSPARENTE de columnas de la base de datos.
 *
 * Un AttributeConverter de JPA se ejecuta automáticamente:
 *   - al GUARDAR:  convertToDatabaseColumn() -> cifra el valor antes del INSERT/UPDATE
 *   - al LEER:     convertToEntityAttribute() -> descifra el valor después del SELECT
 *
 * Así, en el código trabajamos con el texto normal, pero en la base de datos queda cifrado.
 * Si alguien roba un backup de la base, solo ve texto ilegible.
 *
 * Uso en una entidad:   @Convert(converter = EncryptedStringConverter.class)
 *                       private String tokenApi;
 */
@Component
@Converter
public class EncryptedStringConverter implements AttributeConverter<String, String> {

    private final AesGcmEncryptionService encryptionService;

    public EncryptedStringConverter(AesGcmEncryptionService encryptionService) {
        this.encryptionService = encryptionService;
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        return attribute == null ? null : encryptionService.encrypt(attribute);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        return dbData == null ? null : encryptionService.decrypt(dbData);
    }
}
