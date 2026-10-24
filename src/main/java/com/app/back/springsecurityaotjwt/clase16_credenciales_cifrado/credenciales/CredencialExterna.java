package com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.credenciales;

import com.app.back.springsecurityaotjwt.clase16_credenciales_cifrado.crypto.EncryptedStringConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * CLASE 16 - Un dato que hay que RECUPERAR: el token de una API externa de un usuario
 * (por ejemplo, el token que nos dio GitHub o una pasarela de pagos).
 *
 * Como necesitamos volver a usarlo, NO podemos hashearlo: lo CIFRAMOS con AES.
 * El cifrado/descifrado es automático gracias a @Convert(EncryptedStringConverter).
 */
@Entity
@Table(name = "credenciales_externas")
public class CredencialExterna {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Dueño de la credencial (username del usuario autenticado). */
    @Column(nullable = false)
    private String propietario;

    @Column(nullable = false)
    private String servicio;

    /** En la base de datos se guarda CIFRADO (Base64 de IV + texto cifrado). */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "token_api", nullable = false, length = 1024)
    private String tokenApi;

    protected CredencialExterna() {
    }

    public CredencialExterna(String propietario, String servicio, String tokenApi) {
        this.propietario = propietario;
        this.servicio = servicio;
        this.tokenApi = tokenApi;
    }

    public Long getId() {
        return id;
    }

    public String getPropietario() {
        return propietario;
    }

    public String getServicio() {
        return servicio;
    }

    public String getTokenApi() {
        return tokenApi;
    }
}
